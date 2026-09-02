#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>

#include "klog.h" /* IWYU pragma: keep */
#include "provenance/context.h"
#include "supercall/supercall.h"
#include "uapi/provenance.h"
#include "util.h"

#define KSU_PROVENANCE_CONTEXT_HASH_BITS 7
#define KSU_PROVENANCE_TASK_HASH_BITS 10
#define KSU_PROVENANCE_CRED_HASH_BITS 10

#define KSU_PROVENANCE_MAX_CONTEXTS 128U
#define KSU_PROVENANCE_MAX_TASK_BINDINGS 4096U
#define KSU_PROVENANCE_MAX_CREDENTIAL_BINDINGS 4096U
#define KSU_PROVENANCE_MAX_PENDING_LAUNCHES 128U
#define KSU_PROVENANCE_MAX_CONTEXT_TASKS 1024U
#define KSU_PROVENANCE_MAX_CONTEXT_CREDS 1024U
#define KSU_PROVENANCE_DEFAULT_LAUNCH_TIMEOUT_MS 5000U
#define KSU_PROVENANCE_MIN_LAUNCH_TIMEOUT_MS 100U
#define KSU_PROVENANCE_MAX_LAUNCH_TIMEOUT_MS 30000U

struct ksu_provenance_context {
    struct hlist_node cookie_node;
    struct rcu_head rcu;
    refcount_t refs;
    struct ksu_provenance_context_descriptor_v1 descriptor;
    u64 cookie;
    u64 supervisor_generation;
    u32 state;
    u32 gap_reason;
    unsigned int task_count;
    unsigned int cred_count;
    unsigned int pending_launches;
    bool close_requested;
    bool in_registry;
#ifdef MODULE
    bool module_pinned;
#endif
};

struct ksu_provenance_task_binding {
    struct hlist_node node;
    struct rcu_head rcu;
    struct task_struct *task;
    struct ksu_provenance_context *context;
};

struct ksu_provenance_cred_binding {
    struct hlist_node node;
    struct rcu_head rcu;
    const struct cred *cred;
    struct ksu_provenance_context *context;
    bool reserved;
};

struct ksu_provenance_launch_endpoint {
    struct ksu_provenance_context *context;
    u64 supervisor_generation;
    u64 context_cookie;
    u64 expires_ns;
    atomic_t consumed;
    atomic_t pending_counted;
};

struct ksu_provenance_supervisor_endpoint {
    u64 generation;
};

static DEFINE_HASHTABLE(ksu_provenance_contexts, KSU_PROVENANCE_CONTEXT_HASH_BITS);
static DEFINE_HASHTABLE(ksu_provenance_tasks, KSU_PROVENANCE_TASK_HASH_BITS);
static DEFINE_HASHTABLE(ksu_provenance_creds, KSU_PROVENANCE_CRED_HASH_BITS);
static DEFINE_SPINLOCK(ksu_provenance_map_lock);
static DEFINE_SPINLOCK(ksu_provenance_supervisor_lock);

static unsigned int ksu_provenance_context_count;
static unsigned int ksu_provenance_task_count;
static unsigned int ksu_provenance_cred_count;
static unsigned int ksu_provenance_pending_launch_count;

static struct task_struct *ksu_provenance_supervisor_task;
static u64 ksu_provenance_supervisor_generation;
static u32 ksu_provenance_supervisor_status = KSU_PROVENANCE_SUPERVISOR_NONE;
static u32 ksu_provenance_global_gap_reason = KSU_PROVENANCE_GAP_NONE;
static u8 ksu_provenance_boot_epoch[16];
static bool ksu_provenance_selftest_passed;
static bool ksu_provenance_accepting;
static bool ksu_provenance_initialized;
static bool ksu_provenance_io_uring_tested;

static atomic64_t ksu_provenance_reconciliation_failures = ATOMIC64_INIT(0);
static atomic64_t ksu_provenance_allocation_failures = ATOMIC64_INIT(0);

static struct tracepoint *ksu_provenance_sched_fork_tp;
static struct tracepoint *ksu_provenance_sched_exit_tp;
static bool ksu_provenance_sched_fork_registered;
static bool ksu_provenance_sched_exit_registered;

static long ksu_provenance_launch_ioctl(struct file *file, unsigned int cmd,
                                        unsigned long arg);
static int ksu_provenance_launch_release(struct inode *inode, struct file *file);
static long ksu_provenance_supervisor_ioctl(struct file *file, unsigned int cmd,
                                            unsigned long arg);
static int ksu_provenance_supervisor_release(struct inode *inode,
                                             struct file *file);

static const struct file_operations ksu_provenance_launch_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = ksu_provenance_launch_ioctl,
    .compat_ioctl = ksu_provenance_launch_ioctl,
    .release = ksu_provenance_launch_release,
};

static const struct file_operations ksu_provenance_supervisor_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = ksu_provenance_supervisor_ioctl,
    .compat_ioctl = ksu_provenance_supervisor_ioctl,
    .release = ksu_provenance_supervisor_release,
};

static bool ksu_provenance_all_zero(const void *data, size_t size)
{
    const u8 *bytes = data;
    size_t index;

    for (index = 0; index < size; index++) {
        if (bytes[index])
            return false;
    }
    return true;
}

static void ksu_provenance_context_rcu_free(struct rcu_head *rcu)
{
    struct ksu_provenance_context *context =
        container_of(rcu, struct ksu_provenance_context, rcu);

#ifdef MODULE
    if (context->module_pinned)
        module_put(THIS_MODULE);
#endif
    kfree(context);
}

static bool ksu_provenance_context_get(struct ksu_provenance_context *context)
{
    return context && refcount_inc_not_zero(&context->refs);
}

static void ksu_provenance_context_put(struct ksu_provenance_context *context)
{
    if (context && refcount_dec_and_test(&context->refs))
        call_rcu(&context->rcu, ksu_provenance_context_rcu_free);
}

static void ksu_provenance_task_binding_rcu_free(struct rcu_head *rcu)
{
    struct ksu_provenance_task_binding *binding =
        container_of(rcu, struct ksu_provenance_task_binding, rcu);

    ksu_provenance_context_put(binding->context);
    kfree(binding);
}

static void ksu_provenance_cred_binding_rcu_free(struct rcu_head *rcu)
{
    struct ksu_provenance_cred_binding *binding =
        container_of(rcu, struct ksu_provenance_cred_binding, rcu);

    ksu_provenance_context_put(binding->context);
    kfree(binding);
}

static struct ksu_provenance_context *
ksu_provenance_find_context_locked(u64 cookie)
{
    struct ksu_provenance_context *context;

    hash_for_each_possible(ksu_provenance_contexts, context, cookie_node,
                           cookie) {
        if (context->cookie == cookie && context->in_registry)
            return context;
    }
    return NULL;
}

static struct ksu_provenance_task_binding *
ksu_provenance_find_task_locked(const struct task_struct *task)
{
    struct ksu_provenance_task_binding *binding;

    hash_for_each_possible(ksu_provenance_tasks, binding, node,
                           (unsigned long)task) {
        if (binding->task == task)
            return binding;
    }
    return NULL;
}

static struct ksu_provenance_cred_binding *
ksu_provenance_find_cred_locked(const struct cred *cred)
{
    struct ksu_provenance_cred_binding *binding;

    hash_for_each_possible(ksu_provenance_creds, binding, node,
                           (unsigned long)cred) {
        if (binding->cred == cred)
            return binding;
    }
    return NULL;
}

static struct ksu_provenance_context *
ksu_provenance_lookup_task_rcu(const struct task_struct *task)
{
    struct ksu_provenance_task_binding *binding;

    hash_for_each_possible_rcu(ksu_provenance_tasks, binding, node,
                               (unsigned long)task) {
        if (binding->task == task &&
            ksu_provenance_context_get(binding->context))
            return binding->context;
    }
    return NULL;
}

static struct ksu_provenance_context *
ksu_provenance_lookup_cred_rcu(const struct cred *cred)
{
    struct ksu_provenance_cred_binding *binding;

    hash_for_each_possible_rcu(ksu_provenance_creds, binding, node,
                               (unsigned long)cred) {
        if (binding->cred == cred && !READ_ONCE(binding->reserved) &&
            ksu_provenance_context_get(binding->context))
            return binding->context;
    }
    return NULL;
}

static void ksu_provenance_mark_gap(struct ksu_provenance_context *context,
                                    u32 reason)
{
    if (reason == KSU_PROVENANCE_GAP_NONE)
        return;
    WRITE_ONCE(ksu_provenance_global_gap_reason, reason);
    if (context) {
        WRITE_ONCE(context->gap_reason, reason);
        WRITE_ONCE(context->state, KSU_PROVENANCE_CONTEXT_INCOMPLETE);
    }
}

static struct ksu_provenance_context *
ksu_provenance_current_context(bool *conflict)
{
    struct ksu_provenance_context *task_context;
    struct ksu_provenance_context *cred_context;

    *conflict = false;
    rcu_read_lock();
    task_context = ksu_provenance_lookup_task_rcu(current);
    cred_context = ksu_provenance_lookup_cred_rcu(current_cred());
    rcu_read_unlock();

    if (task_context && cred_context && task_context != cred_context) {
        ksu_provenance_mark_gap(task_context,
                                KSU_PROVENANCE_GAP_CONTEXT_CONFLICT);
        ksu_provenance_mark_gap(cred_context,
                                KSU_PROVENANCE_GAP_CONTEXT_CONFLICT);
        ksu_provenance_context_put(cred_context);
        *conflict = true;
        return task_context;
    }
    if (task_context && !cred_context) {
        ksu_provenance_mark_gap(task_context,
                                KSU_PROVENANCE_GAP_CONTEXT_CONFLICT);
        *conflict = true;
        return task_context;
    }
    if (task_context) {
        ksu_provenance_context_put(cred_context);
        return task_context;
    }
    return cred_context;
}

static bool ksu_provenance_context_should_retire_locked(
    struct ksu_provenance_context *context)
{
    if (!context->in_registry || !context->close_requested ||
        context->task_count || context->cred_count ||
        context->pending_launches)
        return false;

    hash_del_rcu(&context->cookie_node);
    context->in_registry = false;
    context->state = KSU_PROVENANCE_CONTEXT_DRAINED;
    if (ksu_provenance_context_count)
        ksu_provenance_context_count--;
    return true;
}

static void ksu_provenance_retire_closed_contexts(void)
{
    struct ksu_provenance_context *context;
    unsigned long irq_flags;
    unsigned int bucket;

    for (;;) {
        context = NULL;
        spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
        hash_for_each(ksu_provenance_contexts, bucket, context,
                      cookie_node) {
            if (ksu_provenance_context_should_retire_locked(context))
                break;
            context = NULL;
        }
        spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
        if (!context)
            return;
        ksu_provenance_context_put(context);
    }
}

static void ksu_provenance_close_context_object(
    struct ksu_provenance_context *context, bool incomplete, u32 gap_reason)
{
    unsigned long irq_flags;
    bool retire;

    spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
    context->close_requested = true;
    if (incomplete) {
        context->gap_reason = gap_reason;
        context->state = KSU_PROVENANCE_CONTEXT_INCOMPLETE;
        ksu_provenance_global_gap_reason = gap_reason;
    } else if (context->state != KSU_PROVENANCE_CONTEXT_INCOMPLETE) {
        context->state = KSU_PROVENANCE_CONTEXT_CLOSED;
    }
    retire = ksu_provenance_context_should_retire_locked(context);
    spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);

    if (retire)
        ksu_provenance_context_put(context);
}

static struct ksu_provenance_context *
ksu_provenance_allocate_context(
    const struct ksu_provenance_context_descriptor_v1 *descriptor,
    u64 supervisor_generation)
{
    struct ksu_provenance_context *context;
    unsigned long irq_flags;
    unsigned int attempts;

#ifdef MODULE
    if (!try_module_get(THIS_MODULE))
        return ERR_PTR(-ENODEV);
#endif
    context = kzalloc(sizeof(*context), GFP_KERNEL);
    if (!context) {
#ifdef MODULE
        module_put(THIS_MODULE);
#endif
        atomic64_inc(&ksu_provenance_allocation_failures);
        return ERR_PTR(-ENOMEM);
    }

    refcount_set(&context->refs, 1);
    context->descriptor = *descriptor;
    context->supervisor_generation = supervisor_generation;
    context->state = KSU_PROVENANCE_CONTEXT_PENDING;
    context->gap_reason = KSU_PROVENANCE_GAP_NONE;
#ifdef MODULE
    context->module_pinned = true;
#endif

    spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
    if (!ksu_provenance_accepting ||
        ksu_provenance_context_count >= KSU_PROVENANCE_MAX_CONTEXTS) {
        spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
        atomic64_inc(&ksu_provenance_allocation_failures);
        ksu_provenance_context_put(context);
        return ERR_PTR(-ENOSPC);
    }
    for (attempts = 0; attempts < 16; attempts++) {
        get_random_bytes(&context->cookie, sizeof(context->cookie));
        if (context->cookie &&
            !ksu_provenance_find_context_locked(context->cookie))
            break;
    }
    if (!context->cookie || attempts == 16) {
        spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
        ksu_provenance_context_put(context);
        return ERR_PTR(-EAGAIN);
    }
    context->in_registry = true;
    hash_add_rcu(ksu_provenance_contexts, &context->cookie_node,
                 context->cookie);
    ksu_provenance_context_count++;
    spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
    return context;
}

static bool ksu_provenance_descriptor_valid(
    const struct ksu_provenance_context_descriptor_v1 *descriptor)
{
    if (descriptor->size != sizeof(*descriptor) ||
        descriptor->version != KSU_PROVENANCE_UAPI_VERSION ||
        descriptor->flags || descriptor->reserved0 ||
        descriptor->stage < KSU_PROVENANCE_STAGE_INSTALL ||
        descriptor->stage > KSU_PROVENANCE_STAGE_INIT_EXEC ||
        !ksu_provenance_all_zero(descriptor->reserved1,
                                 sizeof(descriptor->reserved1)))
        return false;
    if (ksu_provenance_all_zero(descriptor->actor_id,
                                sizeof(descriptor->actor_id)) ||
        ksu_provenance_all_zero(descriptor->subject_id,
                                sizeof(descriptor->subject_id)) ||
        ksu_provenance_all_zero(descriptor->script_sha256,
                                sizeof(descriptor->script_sha256)))
        return false;
    return true;
}

static int ksu_provenance_insert_task_binding(
    struct task_struct *task, struct ksu_provenance_context *context,
    gfp_t gfp)
{
    struct ksu_provenance_task_binding *binding;
    unsigned long irq_flags;

    binding = kzalloc(sizeof(*binding), gfp);
    if (!binding) {
        atomic64_inc(&ksu_provenance_allocation_failures);
        ksu_provenance_mark_gap(context,
                                KSU_PROVENANCE_GAP_ALLOCATION_FAILURE);
        return -ENOMEM;
    }
    binding->task = task;
    binding->context = context;

    spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
    if (!ksu_provenance_accepting ||
        ksu_provenance_task_count >= KSU_PROVENANCE_MAX_TASK_BINDINGS ||
        context->task_count >= KSU_PROVENANCE_MAX_CONTEXT_TASKS) {
        spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
        kfree(binding);
        atomic64_inc(&ksu_provenance_allocation_failures);
        ksu_provenance_mark_gap(context,
                                KSU_PROVENANCE_GAP_ALLOCATION_FAILURE);
        return -ENOSPC;
    }
    if (ksu_provenance_find_task_locked(task)) {
        spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
        kfree(binding);
        ksu_provenance_mark_gap(context,
                                KSU_PROVENANCE_GAP_CONTEXT_CONFLICT);
        return -EEXIST;
    }
    if (!ksu_provenance_context_get(context)) {
        spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
        kfree(binding);
        return -ESTALE;
    }
    hash_add_rcu(ksu_provenance_tasks, &binding->node,
                 (unsigned long)task);
    context->task_count++;
    ksu_provenance_task_count++;
    spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
    return 0;
}

static int ksu_provenance_insert_cred_binding(
    const struct cred *cred, struct ksu_provenance_context *context,
    bool reserved, gfp_t gfp)
{
    struct ksu_provenance_cred_binding *binding;
    unsigned long irq_flags;

    binding = kzalloc(sizeof(*binding), gfp);
    if (!binding) {
        atomic64_inc(&ksu_provenance_allocation_failures);
        ksu_provenance_mark_gap(context,
                                KSU_PROVENANCE_GAP_ALLOCATION_FAILURE);
        return -ENOMEM;
    }
    binding->cred = cred;
    binding->context = context;
    binding->reserved = reserved;

    spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
    if (!ksu_provenance_accepting ||
        ksu_provenance_cred_count >=
            KSU_PROVENANCE_MAX_CREDENTIAL_BINDINGS ||
        context->cred_count >= KSU_PROVENANCE_MAX_CONTEXT_CREDS) {
        spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
        kfree(binding);
        atomic64_inc(&ksu_provenance_allocation_failures);
        ksu_provenance_mark_gap(context,
                                KSU_PROVENANCE_GAP_ALLOCATION_FAILURE);
        return -ENOSPC;
    }
    if (ksu_provenance_find_cred_locked(cred)) {
        spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
        kfree(binding);
        ksu_provenance_mark_gap(context,
                                KSU_PROVENANCE_GAP_CONTEXT_CONFLICT);
        return -EEXIST;
    }
    if (!ksu_provenance_context_get(context)) {
        spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
        kfree(binding);
        return -ESTALE;
    }
    hash_add_rcu(ksu_provenance_creds, &binding->node,
                 (unsigned long)cred);
    context->cred_count++;
    ksu_provenance_cred_count++;
    spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
    return 0;
}

static void ksu_provenance_remove_task_binding(struct task_struct *task)
{
    struct ksu_provenance_task_binding *binding;
    struct ksu_provenance_context *context = NULL;
    unsigned long irq_flags;
    bool retire = false;

    spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
    binding = ksu_provenance_find_task_locked(task);
    if (binding) {
        context = binding->context;
        hash_del_rcu(&binding->node);
        if (context->task_count)
            context->task_count--;
        if (ksu_provenance_task_count)
            ksu_provenance_task_count--;
        retire = ksu_provenance_context_should_retire_locked(context);
    }
    spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);

    if (!binding)
        return;
    call_rcu(&binding->rcu, ksu_provenance_task_binding_rcu_free);
    if (retire)
        ksu_provenance_context_put(context);
}

static void ksu_provenance_remove_cred_binding(const struct cred *cred)
{
    struct ksu_provenance_cred_binding *binding;
    struct ksu_provenance_context *context = NULL;
    unsigned long irq_flags;
    bool retire = false;

    spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
    binding = ksu_provenance_find_cred_locked(cred);
    if (binding) {
        context = binding->context;
        hash_del_rcu(&binding->node);
        if (context->cred_count)
            context->cred_count--;
        if (ksu_provenance_cred_count)
            ksu_provenance_cred_count--;
        retire = ksu_provenance_context_should_retire_locked(context);
    }
    spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);

    if (!binding)
        return;
    call_rcu(&binding->rcu, ksu_provenance_cred_binding_rcu_free);
    if (retire)
        ksu_provenance_context_put(context);
}

int ksu_provenance_task_alloc(struct task_struct *task)
{
    struct ksu_provenance_context *context;
    bool conflict;
    int error;

    if (!READ_ONCE(ksu_provenance_accepting))
        return 0;
    context = ksu_provenance_current_context(&conflict);
    if (!context)
        return 0;
    if (conflict) {
        ksu_provenance_context_put(context);
        return -EUCLEAN;
    }
    if (READ_ONCE(context->close_requested)) {
        ksu_provenance_context_put(context);
        return -ECANCELED;
    }
    error = ksu_provenance_insert_task_binding(task, context, GFP_KERNEL);
    ksu_provenance_context_put(context);
    return error;
}

void ksu_provenance_task_free(struct task_struct *task)
{
    ksu_provenance_remove_task_binding(task);
}

int ksu_provenance_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
    struct ksu_provenance_context *context;
    bool conflict;
    int error;

    if (!READ_ONCE(ksu_provenance_accepting))
        return 0;
    context = ksu_provenance_current_context(&conflict);
    if (!context)
        return 0;
    if (conflict) {
        ksu_provenance_context_put(context);
        return -EUCLEAN;
    }
    error = ksu_provenance_insert_cred_binding(cred, context, true, gfp);
    ksu_provenance_context_put(context);
    return error;
}

int ksu_provenance_cred_prepare(struct cred *new, const struct cred *old,
                                gfp_t gfp)
{
    struct ksu_provenance_context *context;
    int error = 0;

    if (!READ_ONCE(ksu_provenance_accepting))
        return 0;
    rcu_read_lock();
    context = ksu_provenance_lookup_cred_rcu(old);
    rcu_read_unlock();
    if (!context)
        return 0;
    error = ksu_provenance_insert_cred_binding(new, context, false, gfp);
    ksu_provenance_context_put(context);
    return error;
}

void ksu_provenance_cred_transfer(struct cred *new, const struct cred *old)
{
    struct ksu_provenance_cred_binding *reserved;
    struct ksu_provenance_context *old_context;
    struct ksu_provenance_context *reserved_context = NULL;
    unsigned long irq_flags;
    bool remove = false;
    bool retire = false;

    if (!READ_ONCE(ksu_provenance_accepting))
        return;
    rcu_read_lock();
    old_context = ksu_provenance_lookup_cred_rcu(old);
    rcu_read_unlock();

    spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
    reserved = ksu_provenance_find_cred_locked(new);
    if (reserved)
        reserved_context = reserved->context;
    if (old_context && reserved && reserved->reserved &&
        reserved_context == old_context) {
        WRITE_ONCE(reserved->reserved, false);
    } else if (reserved) {
        hash_del_rcu(&reserved->node);
        if (reserved_context->cred_count)
            reserved_context->cred_count--;
        if (ksu_provenance_cred_count)
            ksu_provenance_cred_count--;
        remove = true;
        retire = ksu_provenance_context_should_retire_locked(
            reserved_context);
    }
    spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);

    if (old_context && (!reserved || reserved_context != old_context)) {
        ksu_provenance_mark_gap(old_context,
                                KSU_PROVENANCE_GAP_CONTEXT_CONFLICT);
    }
    if (reserved_context && reserved_context != old_context) {
        ksu_provenance_mark_gap(reserved_context,
                                KSU_PROVENANCE_GAP_CONTEXT_CONFLICT);
    }
    if (remove)
        call_rcu(&reserved->rcu, ksu_provenance_cred_binding_rcu_free);
    if (retire)
        ksu_provenance_context_put(reserved_context);
    if (old_context)
        ksu_provenance_context_put(old_context);
}

void ksu_provenance_cred_free(struct cred *cred)
{
    ksu_provenance_remove_cred_binding(cred);
}

bool ksu_provenance_current_is_tagged(void)
{
    struct ksu_provenance_context *context;
    bool conflict;

    context = ksu_provenance_current_context(&conflict);
    if (!context)
        return false;
    ksu_provenance_context_put(context);
    return true;
}

bool ksu_provenance_task_is_supervisor(const struct task_struct *task)
{
    u32 state = READ_ONCE(ksu_provenance_supervisor_status);

    return (state == KSU_PROVENANCE_SUPERVISOR_CLAIMED ||
            state == KSU_PROVENANCE_SUPERVISOR_READY) &&
           READ_ONCE(ksu_provenance_supervisor_task) == task;
}

bool ksu_provenance_current_is_supervisor(void)
{
    return ksu_provenance_task_is_supervisor(current);
}

bool ksu_provenance_is_control_file(const struct file *file)
{
    return file && (file->f_op == &ksu_provenance_launch_fops ||
                    file->f_op == &ksu_provenance_supervisor_fops ||
                    ksu_is_driver_file(file));
}

void ksu_provenance_note_descriptor_receive(const struct file *file)
{
    struct ksu_provenance_context *context;
    bool conflict;

    if (!ksu_provenance_is_control_file(file))
        return;
    context = ksu_provenance_current_context(&conflict);
    if (!context)
        return;
    ksu_provenance_mark_gap(context, KSU_PROVENANCE_GAP_DELEGATION);
    ksu_provenance_context_put(context);
}

static void ksu_provenance_mark_supervisor_lost(u64 generation)
{
    struct task_struct *task = NULL;
    struct ksu_provenance_context *context;
    unsigned long irq_flags;
    unsigned int bucket;

    spin_lock_irqsave(&ksu_provenance_supervisor_lock, irq_flags);
    if (ksu_provenance_supervisor_generation != generation ||
        (ksu_provenance_supervisor_status !=
             KSU_PROVENANCE_SUPERVISOR_CLAIMED &&
         ksu_provenance_supervisor_status !=
             KSU_PROVENANCE_SUPERVISOR_READY)) {
        spin_unlock_irqrestore(&ksu_provenance_supervisor_lock, irq_flags);
        return;
    }
    task = ksu_provenance_supervisor_task;
    ksu_provenance_supervisor_task = NULL;
    ksu_provenance_supervisor_status = KSU_PROVENANCE_SUPERVISOR_LOST;
    ksu_provenance_global_gap_reason =
        KSU_PROVENANCE_GAP_SUPERVISOR_LOSS;
    spin_unlock_irqrestore(&ksu_provenance_supervisor_lock, irq_flags);

    spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
    hash_for_each(ksu_provenance_contexts, bucket, context, cookie_node) {
        if (context->supervisor_generation == generation) {
            context->close_requested = true;
            context->state = KSU_PROVENANCE_CONTEXT_INCOMPLETE;
            context->gap_reason = KSU_PROVENANCE_GAP_SUPERVISOR_LOSS;
        }
    }
    spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);

    ksu_provenance_retire_closed_contexts();

    if (task)
        put_task_struct(task);
}

void ksu_provenance_note_task_exit(struct task_struct *task)
{
    u64 generation;

    if (READ_ONCE(ksu_provenance_supervisor_task) != task)
        return;
    generation = READ_ONCE(ksu_provenance_supervisor_generation);
    ksu_provenance_mark_supervisor_lost(generation);
}

static int ksu_provenance_install_supervisor_endpoint(u64 generation)
{
    struct ksu_provenance_supervisor_endpoint *endpoint;
    struct file *file;
    int fd;

    endpoint = kzalloc(sizeof(*endpoint), GFP_KERNEL);
    if (!endpoint)
        return -ENOMEM;
    endpoint->generation = generation;

    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) {
        kfree(endpoint);
        return fd;
    }
    file = anon_inode_getfile("[ksu_provenance_supervisor]",
                              &ksu_provenance_supervisor_fops, endpoint,
                              O_RDWR | O_CLOEXEC);
    if (IS_ERR(file)) {
        put_unused_fd(fd);
        kfree(endpoint);
        return PTR_ERR(file);
    }
    fd_install(fd, file);
    return fd;
}

int ksu_provenance_claim_supervisor(
    const struct ksu_provenance_verified_image *image,
    u64 eligibility_generation,
    struct ksu_provenance_claim_result_v1 *result)
{
    struct task_struct *task;
    unsigned long irq_flags;
    u64 generation;
    int fd;

    if (!image || !(image->roles & KSU_PROVENANCE_ROLE_SUPERVISOR) ||
        !ksu_provenance_core_ready()) {
        result->result = KSU_PROVENANCE_CLAIM_CORE_PROVIDER_NOT_READY;
        return -EAGAIN;
    }

    spin_lock_irqsave(&ksu_provenance_supervisor_lock, irq_flags);
    if (ksu_provenance_supervisor_status !=
        KSU_PROVENANCE_SUPERVISOR_NONE) {
        spin_unlock_irqrestore(&ksu_provenance_supervisor_lock, irq_flags);
        result->result = KSU_PROVENANCE_CLAIM_ALREADY_CLAIMED;
        return -EALREADY;
    }
    generation = ksu_provenance_supervisor_generation + 1;
    if (!generation)
        generation = 1;
    spin_unlock_irqrestore(&ksu_provenance_supervisor_lock, irq_flags);

    fd = ksu_provenance_install_supervisor_endpoint(generation);
    if (fd < 0) {
        result->result = KSU_PROVENANCE_CLAIM_INTERNAL;
        return fd;
    }

    task = current;
    get_task_struct(task);
    spin_lock_irqsave(&ksu_provenance_supervisor_lock, irq_flags);
    if (ksu_provenance_supervisor_status !=
        KSU_PROVENANCE_SUPERVISOR_NONE) {
        spin_unlock_irqrestore(&ksu_provenance_supervisor_lock, irq_flags);
        put_task_struct(task);
        ksu_close_fd(fd);
        result->result = KSU_PROVENANCE_CLAIM_ALREADY_CLAIMED;
        return -EALREADY;
    }
    ksu_provenance_supervisor_task = task;
    ksu_provenance_supervisor_generation = generation;
    ksu_provenance_supervisor_status = KSU_PROVENANCE_SUPERVISOR_CLAIMED;
    spin_unlock_irqrestore(&ksu_provenance_supervisor_lock, irq_flags);

    result->result = KSU_PROVENANCE_CLAIM_RESULT_OK;
    result->eligibility_generation = eligibility_generation;
    result->endpoint_fd = fd;
    result->supervisor_state = KSU_PROVENANCE_SUPERVISOR_CLAIMED;
    return 0;
}

void ksu_provenance_fail_supervisor_claim(void)
{
    unsigned long irq_flags;

    spin_lock_irqsave(&ksu_provenance_supervisor_lock, irq_flags);
    if (ksu_provenance_supervisor_status ==
        KSU_PROVENANCE_SUPERVISOR_NONE)
        ksu_provenance_supervisor_status =
            KSU_PROVENANCE_SUPERVISOR_FAILED;
    spin_unlock_irqrestore(&ksu_provenance_supervisor_lock, irq_flags);
}

static bool ksu_provenance_supervisor_parent_of_current(void)
{
    struct task_struct *parent;
    struct task_struct *supervisor;
    bool matches;

    supervisor = READ_ONCE(ksu_provenance_supervisor_task);
    if (!supervisor)
        return false;
    rcu_read_lock();
    parent = rcu_dereference(current->real_parent);
    matches = parent == supervisor;
    rcu_read_unlock();
    return matches;
}

static int ksu_provenance_activate_context(
    struct ksu_provenance_launch_endpoint *endpoint,
    const struct ksu_provenance_activate_v1 *request,
    struct ksu_provenance_activate_result_v1 *result)
{
    struct ksu_provenance_context *context = endpoint->context;
    struct cred *new_cred;
    int error;

    if (request->size != sizeof(*request) ||
        request->version != KSU_PROVENANCE_UAPI_VERSION || request->flags ||
        !ksu_provenance_all_zero(request->reserved,
                                 sizeof(request->reserved)))
        return -EINVAL;
    if (request->supervisor_generation != endpoint->supervisor_generation ||
        request->context_cookie != endpoint->context_cookie)
        return -ESTALE;
    if (ktime_get_ns() > endpoint->expires_ns)
        return -ETIMEDOUT;
    if ((READ_ONCE(ksu_provenance_supervisor_status) !=
             KSU_PROVENANCE_SUPERVISOR_CLAIMED &&
         READ_ONCE(ksu_provenance_supervisor_status) !=
             KSU_PROVENANCE_SUPERVISOR_READY) ||
        READ_ONCE(ksu_provenance_supervisor_generation) !=
            endpoint->supervisor_generation)
        return -EOWNERDEAD;
    if (READ_ONCE(context->close_requested))
        return -ECANCELED;
    if (!ksu_provenance_supervisor_parent_of_current())
        return -EPERM;
    if (atomic_cmpxchg(&endpoint->consumed, 0, 1))
        return -EALREADY;

    new_cred = prepare_creds();
    if (!new_cred) {
        error = -ENOMEM;
        goto fail_closed;
    }
    error = ksu_provenance_insert_task_binding(current, context, GFP_KERNEL);
    if (error)
        goto abort_cred;
    error = ksu_provenance_insert_cred_binding(new_cred, context, false,
                                               GFP_KERNEL);
    if (error) {
        ksu_provenance_remove_task_binding(current);
        goto abort_cred;
    }
    commit_creds(new_cred);

    WRITE_ONCE(context->state, KSU_PROVENANCE_CONTEXT_ACTIVE);
    if (atomic_cmpxchg(&endpoint->pending_counted, 1, 0) == 1) {
        unsigned long irq_flags;

        spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
        if (context->pending_launches)
            context->pending_launches--;
        if (ksu_provenance_pending_launch_count)
            ksu_provenance_pending_launch_count--;
        spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
    }

    memset(result, 0, sizeof(*result));
    result->size = sizeof(*result);
    result->version = KSU_PROVENANCE_UAPI_VERSION;
    result->context_state = KSU_PROVENANCE_CONTEXT_ACTIVE;
    result->supervisor_generation = endpoint->supervisor_generation;
    result->context_cookie = endpoint->context_cookie;
    return 0;

abort_cred:
    abort_creds(new_cred);
fail_closed:
    atomic64_inc(&ksu_provenance_allocation_failures);
    ksu_provenance_close_context_object(
        context, true, KSU_PROVENANCE_GAP_ALLOCATION_FAILURE);
    return error;
}

static long ksu_provenance_launch_ioctl(struct file *file, unsigned int cmd,
                                        unsigned long arg)
{
    struct ksu_provenance_launch_endpoint *endpoint = file->private_data;
    struct ksu_provenance_control_cmd_v1 command;
    struct ksu_provenance_activate_v1 request;
    struct ksu_provenance_activate_result_v1 result;
    int error;

    if (cmd != KSU_IOCTL_PROVENANCE_CONTROL)
        return -ENOTTY;
    if (copy_from_user(&command, (void __user *)arg, sizeof(command)))
        return -EFAULT;
    if (command.size != sizeof(command) ||
        command.version != KSU_PROVENANCE_UAPI_VERSION || command.flags ||
        command.operation != KSU_PROVENANCE_CONTROL_ACTIVATE ||
        command.request_size != sizeof(request) ||
        command.response_size != sizeof(result) || !command.request ||
        !command.response ||
        !ksu_provenance_all_zero(command.reserved,
                                 sizeof(command.reserved)))
        return -EINVAL;
    if (copy_from_user(&request, u64_to_user_ptr(command.request),
                       sizeof(request)))
        return -EFAULT;
    error = ksu_provenance_activate_context(endpoint, &request, &result);
    if (error)
        return error;
    if (copy_to_user(u64_to_user_ptr(command.response), &result,
                     sizeof(result)))
        return -EFAULT;
    return 0;
}

static int ksu_provenance_launch_release(struct inode *inode, struct file *file)
{
    struct ksu_provenance_launch_endpoint *endpoint = file->private_data;
    struct ksu_provenance_context *context;

    if (!endpoint)
        return 0;
    context = endpoint->context;
    if (atomic_cmpxchg(&endpoint->pending_counted, 1, 0) == 1) {
        unsigned long irq_flags;

        spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
        if (context->pending_launches)
            context->pending_launches--;
        if (ksu_provenance_pending_launch_count)
            ksu_provenance_pending_launch_count--;
        spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
        ksu_provenance_close_context_object(
            context, true, KSU_PROVENANCE_GAP_UNSUPPORTED_OPERATION);
    }
    ksu_provenance_context_put(context);
    kfree(endpoint);
    return 0;
}

static int ksu_provenance_create_launch(
    const struct ksu_provenance_create_launch_v1 *request,
    struct ksu_provenance_create_launch_result_v1 *result)
{
    struct ksu_provenance_launch_endpoint *endpoint;
    struct ksu_provenance_context *context;
    struct file *file;
    unsigned long irq_flags;
    u32 timeout_ms;
    u64 generation;
    int fd;

    if (!ksu_provenance_current_is_supervisor())
        return -EPERM;
    if (request->size != sizeof(*request) ||
        request->version != KSU_PROVENANCE_UAPI_VERSION || request->flags ||
        request->reserved0 ||
        !ksu_provenance_all_zero(request->reserved,
                                 sizeof(request->reserved)) ||
        !ksu_provenance_descriptor_valid(&request->descriptor))
        return -EINVAL;

    timeout_ms = request->timeout_ms ?: KSU_PROVENANCE_DEFAULT_LAUNCH_TIMEOUT_MS;
    if (timeout_ms < KSU_PROVENANCE_MIN_LAUNCH_TIMEOUT_MS ||
        timeout_ms > KSU_PROVENANCE_MAX_LAUNCH_TIMEOUT_MS)
        return -ERANGE;
    generation = READ_ONCE(ksu_provenance_supervisor_generation);
    context = ksu_provenance_allocate_context(&request->descriptor,
                                              generation);
    if (IS_ERR(context))
        return PTR_ERR(context);

    endpoint = kzalloc(sizeof(*endpoint), GFP_KERNEL);
    if (!endpoint) {
        ksu_provenance_close_context_object(
            context, true, KSU_PROVENANCE_GAP_ALLOCATION_FAILURE);
        return -ENOMEM;
    }
    if (!ksu_provenance_context_get(context)) {
        kfree(endpoint);
        ksu_provenance_close_context_object(
            context, true, KSU_PROVENANCE_GAP_PROVIDER_LOSS);
        return -ESTALE;
    }
    endpoint->context = context;
    endpoint->supervisor_generation = generation;
    endpoint->context_cookie = context->cookie;
    endpoint->expires_ns = ktime_get_ns() + (u64)timeout_ms * NSEC_PER_MSEC;
    atomic_set(&endpoint->consumed, 0);
    atomic_set(&endpoint->pending_counted, 1);

    spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
    if (ksu_provenance_pending_launch_count >=
        KSU_PROVENANCE_MAX_PENDING_LAUNCHES) {
        spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
        atomic_set(&endpoint->pending_counted, 0);
        ksu_provenance_context_put(context);
        kfree(endpoint);
        ksu_provenance_close_context_object(
            context, true, KSU_PROVENANCE_GAP_ALLOCATION_FAILURE);
        return -ENOSPC;
    }
    context->pending_launches++;
    ksu_provenance_pending_launch_count++;
    spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);

    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0)
        goto fail_endpoint;
    file = anon_inode_getfile("[ksu_provenance_launch]",
                              &ksu_provenance_launch_fops, endpoint,
                              O_RDWR | O_CLOEXEC);
    if (IS_ERR(file)) {
        put_unused_fd(fd);
        fd = PTR_ERR(file);
        goto fail_endpoint;
    }
    fd_install(fd, file);

    memset(result, 0, sizeof(*result));
    result->size = sizeof(*result);
    result->version = KSU_PROVENANCE_UAPI_VERSION;
    result->endpoint_fd = fd;
    result->context_state = KSU_PROVENANCE_CONTEXT_PENDING;
    result->supervisor_generation = generation;
    result->context_cookie = context->cookie;
    return 0;

fail_endpoint:
    if (atomic_cmpxchg(&endpoint->pending_counted, 1, 0) == 1) {
        spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
        if (context->pending_launches)
            context->pending_launches--;
        if (ksu_provenance_pending_launch_count)
            ksu_provenance_pending_launch_count--;
        spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
    }
    ksu_provenance_context_put(context);
    kfree(endpoint);
    ksu_provenance_close_context_object(
        context, true, KSU_PROVENANCE_GAP_ALLOCATION_FAILURE);
    return fd;
}

static int ksu_provenance_close_context(
    const struct ksu_provenance_close_context_v1 *request)
{
    struct ksu_provenance_context *context;
    unsigned long irq_flags;

    if (!ksu_provenance_current_is_supervisor())
        return -EPERM;
    if (request->size != sizeof(*request) ||
        request->version != KSU_PROVENANCE_UAPI_VERSION || request->flags ||
        !ksu_provenance_all_zero(request->reserved,
                                 sizeof(request->reserved)))
        return -EINVAL;
    if (request->supervisor_generation !=
        READ_ONCE(ksu_provenance_supervisor_generation))
        return -ESTALE;

    spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
    context = ksu_provenance_find_context_locked(request->context_cookie);
    if (context && !ksu_provenance_context_get(context))
        context = NULL;
    spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
    if (!context)
        return -ENOENT;
    if (context->supervisor_generation != request->supervisor_generation) {
        ksu_provenance_context_put(context);
        return -ESTALE;
    }
    ksu_provenance_close_context_object(context, false,
                                        KSU_PROVENANCE_GAP_NONE);
    ksu_provenance_context_put(context);
    return 0;
}

int ksu_provenance_context_handle_control(
    struct ksu_provenance_control_cmd_v1 *command)
{
    if (command->operation == KSU_PROVENANCE_CONTROL_CREATE_LAUNCH) {
        struct ksu_provenance_create_launch_v1 request;
        struct ksu_provenance_create_launch_result_v1 result;
        int error;

        if (command->request_size != sizeof(request) ||
            command->response_size != sizeof(result) || !command->request ||
            !command->response)
            return -EMSGSIZE;
        if (copy_from_user(&request, u64_to_user_ptr(command->request),
                           sizeof(request)))
            return -EFAULT;
        error = ksu_provenance_create_launch(&request, &result);
        if (error)
            return error;
        if (copy_to_user(u64_to_user_ptr(command->response), &result,
                         sizeof(result))) {
            ksu_close_fd(result.endpoint_fd);
            return -EFAULT;
        }
        return 0;
    }
    if (command->operation == KSU_PROVENANCE_CONTROL_CLOSE_CONTEXT) {
        struct ksu_provenance_close_context_v1 request;

        if (command->request_size != sizeof(request) ||
            command->response_size || !command->request)
            return -EMSGSIZE;
        if (copy_from_user(&request, u64_to_user_ptr(command->request),
                           sizeof(request)))
            return -EFAULT;
        return ksu_provenance_close_context(&request);
    }
    if (command->operation == KSU_PROVENANCE_CONTROL_QUERY_CONTEXT) {
        struct ksu_provenance_context_status_v1 status;

        if (command->request_size ||
            command->response_size != sizeof(status) || command->request ||
            !command->response)
            return -EMSGSIZE;
        ksu_provenance_fill_context_status(&status);
        if (copy_to_user(u64_to_user_ptr(command->response), &status,
                         sizeof(status)))
            return -EFAULT;
        return 0;
    }
    if (command->operation == KSU_PROVENANCE_CONTROL_SUPERVISOR_READY) {
        struct ksu_provenance_supervisor_ready_v1 request;
        unsigned long irq_flags;

        if (command->request_size != sizeof(request) ||
            command->response_size || !command->request)
            return -EMSGSIZE;
        if (copy_from_user(&request, u64_to_user_ptr(command->request),
                           sizeof(request)))
            return -EFAULT;
        if (request.size != sizeof(request) ||
            request.version != KSU_PROVENANCE_UAPI_VERSION ||
            request.flags != KSU_PROVENANCE_READY_IO_URING_TESTED ||
            !ksu_provenance_all_zero(request.reserved,
                                     sizeof(request.reserved)))
            return -EINVAL;
        if (!ksu_provenance_current_is_supervisor())
            return -EPERM;
        if (request.supervisor_generation !=
            READ_ONCE(ksu_provenance_supervisor_generation))
            return -ESTALE;
        if (READ_ONCE(ksu_provenance_global_gap_reason) !=
                KSU_PROVENANCE_GAP_NONE ||
            READ_ONCE(ksu_provenance_context_count) ||
            READ_ONCE(ksu_provenance_task_count) ||
            READ_ONCE(ksu_provenance_cred_count) ||
            READ_ONCE(ksu_provenance_pending_launch_count))
            return -EUCLEAN;
        spin_lock_irqsave(&ksu_provenance_supervisor_lock, irq_flags);
        if (ksu_provenance_supervisor_status !=
            KSU_PROVENANCE_SUPERVISOR_CLAIMED) {
            spin_unlock_irqrestore(&ksu_provenance_supervisor_lock,
                                   irq_flags);
            return -EALREADY;
        }
        WRITE_ONCE(ksu_provenance_io_uring_tested, true);
        smp_store_release(&ksu_provenance_supervisor_status,
                          KSU_PROVENANCE_SUPERVISOR_READY);
        spin_unlock_irqrestore(&ksu_provenance_supervisor_lock, irq_flags);
        return 0;
    }
    return -EOPNOTSUPP;
}

static long ksu_provenance_supervisor_ioctl(struct file *file,
                                            unsigned int cmd,
                                            unsigned long arg)
{
    struct ksu_provenance_supervisor_endpoint *endpoint = file->private_data;
    struct ksu_provenance_control_cmd_v1 command;

    if (!endpoint || endpoint->generation !=
                         READ_ONCE(ksu_provenance_supervisor_generation) ||
        !ksu_provenance_current_is_supervisor())
        return -EPERM;
    if (cmd == KSU_IOCTL_PROVENANCE_GET_CONTEXT_STATUS) {
        struct ksu_provenance_context_status_v1 status;

        ksu_provenance_fill_context_status(&status);
        if (copy_to_user((void __user *)arg, &status, sizeof(status)))
            return -EFAULT;
        return 0;
    }
    if (cmd != KSU_IOCTL_PROVENANCE_CONTROL)
        return -ENOTTY;
    if (copy_from_user(&command, (void __user *)arg, sizeof(command)))
        return -EFAULT;
    if (command.size != sizeof(command) ||
        command.version != KSU_PROVENANCE_UAPI_VERSION || command.flags ||
        !ksu_provenance_all_zero(command.reserved,
                                 sizeof(command.reserved)))
        return -EINVAL;
    return ksu_provenance_context_handle_control(&command);
}

static int ksu_provenance_supervisor_release(struct inode *inode,
                                             struct file *file)
{
    struct ksu_provenance_supervisor_endpoint *endpoint = file->private_data;

    if (endpoint) {
        ksu_provenance_mark_supervisor_lost(endpoint->generation);
        kfree(endpoint);
    }
    return 0;
}

static void ksu_provenance_tracepoint_find(struct tracepoint *tracepoint,
                                           void *private)
{
    if (!strcmp(tracepoint->name, "sched_process_fork"))
        ksu_provenance_sched_fork_tp = tracepoint;
    else if (!strcmp(tracepoint->name, "sched_process_exit"))
        ksu_provenance_sched_exit_tp = tracepoint;
}

static void ksu_provenance_sched_process_fork(void *private,
                                              struct task_struct *parent,
                                              struct task_struct *child)
{
    struct ksu_provenance_context *parent_context;
    struct ksu_provenance_context *child_context;

    rcu_read_lock();
    parent_context = ksu_provenance_lookup_task_rcu(parent);
    child_context = ksu_provenance_lookup_task_rcu(child);
    rcu_read_unlock();
    if (!!parent_context != !!child_context ||
        (parent_context && child_context && parent_context != child_context)) {
        atomic64_inc(&ksu_provenance_reconciliation_failures);
        ksu_provenance_mark_gap(parent_context ?: child_context,
                                KSU_PROVENANCE_GAP_CONTEXT_CONFLICT);
    }
    ksu_provenance_context_put(parent_context);
    ksu_provenance_context_put(child_context);
}

static void ksu_provenance_sched_process_exit(void *private,
                                              struct task_struct *task)
{
    ksu_provenance_note_task_exit(task);
}

static int ksu_provenance_register_tracepoints(void)
{
    int error;

    for_each_kernel_tracepoint(ksu_provenance_tracepoint_find, NULL);
    if (!ksu_provenance_sched_fork_tp || !ksu_provenance_sched_exit_tp)
        return -ENOENT;
    error = tracepoint_probe_register(ksu_provenance_sched_fork_tp,
                                      ksu_provenance_sched_process_fork,
                                      NULL);
    if (error)
        return error;
    ksu_provenance_sched_fork_registered = true;
    error = tracepoint_probe_register(ksu_provenance_sched_exit_tp,
                                      ksu_provenance_sched_process_exit,
                                      NULL);
    if (error) {
        tracepoint_probe_unregister(ksu_provenance_sched_fork_tp,
                                    ksu_provenance_sched_process_fork,
                                    NULL);
        ksu_provenance_sched_fork_registered = false;
        tracepoint_synchronize_unregister();
        return error;
    }
    ksu_provenance_sched_exit_registered = true;
    return 0;
}

static void ksu_provenance_unregister_tracepoints(void)
{
    if (ksu_provenance_sched_exit_registered) {
        tracepoint_probe_unregister(ksu_provenance_sched_exit_tp,
                                    ksu_provenance_sched_process_exit,
                                    NULL);
        ksu_provenance_sched_exit_registered = false;
    }
    if (ksu_provenance_sched_fork_registered) {
        tracepoint_probe_unregister(ksu_provenance_sched_fork_tp,
                                    ksu_provenance_sched_process_fork,
                                    NULL);
        ksu_provenance_sched_fork_registered = false;
    }
    tracepoint_synchronize_unregister();
    ksu_provenance_sched_fork_tp = NULL;
    ksu_provenance_sched_exit_tp = NULL;
}

int ksu_provenance_context_selftest(void)
{
    struct ksu_provenance_context_descriptor_v1 descriptor = { 0 };
    struct ksu_provenance_context *context;
    struct ksu_provenance_context *found;
    int error;

    if (!ksu_provenance_sched_fork_registered ||
        !ksu_provenance_sched_exit_registered)
        return -ENODEV;
    descriptor.size = sizeof(descriptor);
    descriptor.version = KSU_PROVENANCE_UAPI_VERSION;
    descriptor.stage = KSU_PROVENANCE_STAGE_ACTION;
    memset(descriptor.actor_id, 0x11, sizeof(descriptor.actor_id));
    memset(descriptor.subject_id, 0x22, sizeof(descriptor.subject_id));
    memset(descriptor.script_sha256, 0x33,
           sizeof(descriptor.script_sha256));
    if (!ksu_provenance_descriptor_valid(&descriptor))
        return -EINVAL;

    context = ksu_provenance_allocate_context(&descriptor, 1);
    if (IS_ERR(context))
        return PTR_ERR(context);
    error = ksu_provenance_insert_task_binding(current, context, GFP_KERNEL);
    if (error)
        goto close_context;
    error = ksu_provenance_insert_cred_binding(current_cred(), context, false,
                                               GFP_KERNEL);
    if (error)
        goto remove_task;
    rcu_read_lock();
    found = ksu_provenance_lookup_task_rcu(current);
    rcu_read_unlock();
    if (found != context)
        error = -EUCLEAN;
    ksu_provenance_context_put(found);
    ksu_provenance_remove_cred_binding(current_cred());
remove_task:
    ksu_provenance_remove_task_binding(current);
close_context:
    ksu_provenance_close_context_object(context, error != 0,
                                        KSU_PROVENANCE_GAP_PROVIDER_LOSS);
    synchronize_rcu();
    if (!error)
        WRITE_ONCE(ksu_provenance_selftest_passed, true);
    return error;
}

int ksu_provenance_context_init(void)
{
    int error;

    hash_init(ksu_provenance_contexts);
    hash_init(ksu_provenance_tasks);
    hash_init(ksu_provenance_creds);
    ksu_provenance_context_count = 0;
    ksu_provenance_task_count = 0;
    ksu_provenance_cred_count = 0;
    ksu_provenance_pending_launch_count = 0;
    WRITE_ONCE(ksu_provenance_initialized, true);
    ksu_provenance_supervisor_task = NULL;
    ksu_provenance_supervisor_generation = 0;
    ksu_provenance_supervisor_status = KSU_PROVENANCE_SUPERVISOR_NONE;
    ksu_provenance_global_gap_reason = KSU_PROVENANCE_GAP_NONE;
    ksu_provenance_selftest_passed = false;
    ksu_provenance_io_uring_tested = false;
    atomic64_set(&ksu_provenance_reconciliation_failures, 0);
    atomic64_set(&ksu_provenance_allocation_failures, 0);
    get_random_bytes(ksu_provenance_boot_epoch,
                     sizeof(ksu_provenance_boot_epoch));
    if (ksu_provenance_all_zero(ksu_provenance_boot_epoch,
                                sizeof(ksu_provenance_boot_epoch)))
        ksu_provenance_boot_epoch[0] = 1;
    WRITE_ONCE(ksu_provenance_accepting, true);
    error = ksu_provenance_register_tracepoints();
    if (error)
        WRITE_ONCE(ksu_provenance_accepting, false);
    return error;
}

void ksu_provenance_begin_drain(void)
{
    struct ksu_provenance_context *context;
    struct task_struct *task = NULL;
    unsigned long irq_flags;
    unsigned int bucket;

    if (!READ_ONCE(ksu_provenance_initialized))
        return;
    WRITE_ONCE(ksu_provenance_accepting, false);
    spin_lock_irqsave(&ksu_provenance_supervisor_lock, irq_flags);
    if (ksu_provenance_supervisor_status ==
            KSU_PROVENANCE_SUPERVISOR_CLAIMED ||
        ksu_provenance_supervisor_status ==
            KSU_PROVENANCE_SUPERVISOR_READY)
        ksu_provenance_supervisor_status =
            KSU_PROVENANCE_SUPERVISOR_DRAINING;
    task = ksu_provenance_supervisor_task;
    ksu_provenance_supervisor_task = NULL;
    spin_unlock_irqrestore(&ksu_provenance_supervisor_lock, irq_flags);
    if (task)
        put_task_struct(task);

    spin_lock_irqsave(&ksu_provenance_map_lock, irq_flags);
    hash_for_each(ksu_provenance_contexts, bucket, context, cookie_node) {
        context->close_requested = true;
        if (context->state != KSU_PROVENANCE_CONTEXT_INCOMPLETE)
            context->state = KSU_PROVENANCE_CONTEXT_CLOSED;
    }
    spin_unlock_irqrestore(&ksu_provenance_map_lock, irq_flags);
    ksu_provenance_retire_closed_contexts();
}

bool ksu_provenance_can_unload(void)
{
    return !READ_ONCE(ksu_provenance_context_count) &&
           !READ_ONCE(ksu_provenance_task_count) &&
           !READ_ONCE(ksu_provenance_cred_count) &&
           !READ_ONCE(ksu_provenance_pending_launch_count) &&
           READ_ONCE(ksu_provenance_supervisor_status) !=
               KSU_PROVENANCE_SUPERVISOR_CLAIMED &&
           READ_ONCE(ksu_provenance_supervisor_status) !=
               KSU_PROVENANCE_SUPERVISOR_READY;
}

void ksu_provenance_context_exit(void)
{
    if (!READ_ONCE(ksu_provenance_initialized))
        return;
    ksu_provenance_begin_drain();
    ksu_provenance_unregister_tracepoints();
    synchronize_rcu();
    WRITE_ONCE(ksu_provenance_initialized, false);
}

bool ksu_provenance_core_ready(void)
{
    return READ_ONCE(ksu_provenance_accepting) &&
           READ_ONCE(ksu_provenance_selftest_passed) &&
           ksu_provenance_sched_fork_registered &&
           ksu_provenance_sched_exit_registered;
}

u64 ksu_provenance_operational_capabilities(void)
{
    u32 supervisor_state;

    if (!ksu_provenance_core_ready())
        return 0;
    supervisor_state = smp_load_acquire(
        &ksu_provenance_supervisor_status);
    return KSU_PROVENANCE_CAP_SUPERVISOR_CLAIM |
           KSU_PROVENANCE_CAP_TASK_CONTEXT |
           KSU_PROVENANCE_CAP_CREDENTIAL_CONTEXT |
           KSU_PROVENANCE_CAP_LAUNCH_ENDPOINT |
           KSU_PROVENANCE_CAP_CONTROL_ISOLATION |
           KSU_PROVENANCE_CAP_SCHED_RECONCILIATION |
           (supervisor_state == KSU_PROVENANCE_SUPERVISOR_READY &&
                    READ_ONCE(ksu_provenance_io_uring_tested) ?
                KSU_PROVENANCE_CAP_IO_URING_CREDENTIAL : 0);
}

u32 ksu_provenance_supervisor_state(void)
{
    return READ_ONCE(ksu_provenance_supervisor_status);
}

u32 ksu_provenance_last_gap_reason(void)
{
    return READ_ONCE(ksu_provenance_global_gap_reason);
}

void ksu_provenance_get_boot_epoch(u8 boot_epoch[16])
{
    memcpy(boot_epoch, ksu_provenance_boot_epoch, 16);
}

void ksu_provenance_fill_context_status(
    struct ksu_provenance_context_status_v1 *status)
{
    memset(status, 0, sizeof(*status));
    status->size = sizeof(*status);
    status->version = KSU_PROVENANCE_UAPI_VERSION;
    status->supervisor_state = ksu_provenance_supervisor_state();
    status->last_gap_reason = ksu_provenance_last_gap_reason();
    status->supervisor_generation =
        READ_ONCE(ksu_provenance_supervisor_generation);
    status->active_contexts = READ_ONCE(ksu_provenance_context_count);
    status->task_bindings = READ_ONCE(ksu_provenance_task_count);
    status->credential_bindings = READ_ONCE(ksu_provenance_cred_count);
    status->pending_launches = READ_ONCE(ksu_provenance_pending_launch_count);
    status->max_contexts = KSU_PROVENANCE_MAX_CONTEXTS;
    status->max_task_bindings = KSU_PROVENANCE_MAX_TASK_BINDINGS;
    status->max_credential_bindings =
        KSU_PROVENANCE_MAX_CREDENTIAL_BINDINGS;
    status->max_pending_launches = KSU_PROVENANCE_MAX_PENDING_LAUNCHES;
    status->reconciliation_failures =
        atomic64_read(&ksu_provenance_reconciliation_failures);
    status->allocation_failures =
        atomic64_read(&ksu_provenance_allocation_failures);
    ksu_provenance_get_boot_epoch(status->boot_epoch);
}

int ksu_provenance_fill_current_context(
    struct ksu_provenance_current_context_v1 *current_context)
{
    struct ksu_provenance_context *context;
    bool conflict;

    memset(current_context, 0, sizeof(*current_context));
    current_context->size = sizeof(*current_context);
    current_context->version = KSU_PROVENANCE_UAPI_VERSION;
    context = ksu_provenance_current_context(&conflict);
    if (!context)
        return -ENOENT;
    current_context->context_state = READ_ONCE(context->state);
    current_context->gap_reason = READ_ONCE(context->gap_reason);
    current_context->supervisor_generation =
        context->supervisor_generation;
    current_context->context_cookie = context->cookie;
    ksu_provenance_get_boot_epoch(current_context->boot_epoch);
    ksu_provenance_context_put(context);
    return conflict ? -EUCLEAN : 0;
}
