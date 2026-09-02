#include <linux/atomic.h>
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/wait.h>

#include "hook/lsm_hook.h"
#include "provenance/context.h"
#include "provenance/eligibility.h"
#include "provenance/image_verify.h"
#include "provenance/provider_lsm.h"
#include "uapi/provenance.h"

static u32 ksu_provenance_core_hook_state = KSU_PROVENANCE_CORE_HOOK_DISABLED;
static u32 ksu_provenance_core_hook_error = KSU_PROVENANCE_CORE_HOOK_NOT_CONFIGURED;
static atomic_t ksu_provenance_hook_inflight = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(ksu_provenance_hook_wait);
static bool ksu_provenance_hook_accepting;

static void ksu_provenance_hook_leave(void)
{
    if (atomic_dec_and_test(&ksu_provenance_hook_inflight))
        wake_up_all(&ksu_provenance_hook_wait);
}

static bool ksu_provenance_hook_enter(void)
{
    if (!READ_ONCE(ksu_provenance_hook_accepting))
        return false;
    atomic_inc(&ksu_provenance_hook_inflight);
    smp_mb__after_atomic();
    if (!READ_ONCE(ksu_provenance_hook_accepting)) {
        ksu_provenance_hook_leave();
        return false;
    }
    return true;
}

static int ksu_provenance_bprm_check_security(struct linux_binprm *bprm)
{
    if (!ksu_provenance_hook_enter())
        return 0;
    ksu_provenance_consider_exec(bprm);
    ksu_provenance_hook_leave();
    return 0;
}

static int ksu_provenance_task_alloc_callback(struct task_struct *task, unsigned long clone_flags)
{
    int error;

    if (!ksu_provenance_hook_enter())
        return 0;
    error = ksu_provenance_task_alloc(task);
    ksu_provenance_hook_leave();
    return error;
}

static void ksu_provenance_task_free_callback(struct task_struct *task)
{
    if (!ksu_provenance_hook_enter())
        return;
    ksu_provenance_note_task_exit(task);
    ksu_provenance_task_free(task);
    ksu_provenance_hook_leave();
}

static int ksu_provenance_cred_alloc_blank_callback(struct cred *cred, gfp_t gfp)
{
    int error;

    if (!ksu_provenance_hook_enter())
        return 0;
    error = ksu_provenance_cred_alloc_blank(cred, gfp);
    ksu_provenance_hook_leave();
    return error;
}

static int ksu_provenance_cred_prepare_callback(struct cred *new, const struct cred *old, gfp_t gfp)
{
    int error;

    if (!ksu_provenance_hook_enter())
        return 0;
    error = ksu_provenance_cred_prepare(new, old, gfp);
    ksu_provenance_hook_leave();
    return error;
}

static void ksu_provenance_cred_transfer_callback(struct cred *new, const struct cred *old)
{
    if (!ksu_provenance_hook_enter())
        return;
    ksu_provenance_cred_transfer(new, old);
    ksu_provenance_hook_leave();
}

static void ksu_provenance_cred_free_callback(struct cred *cred)
{
    if (!ksu_provenance_hook_enter())
        return;
    ksu_provenance_cred_free(cred);
    ksu_provenance_hook_leave();
}

static int ksu_provenance_ptrace_access_check(struct task_struct *child, unsigned int mode)
{
    int error = 0;

    if (!ksu_provenance_hook_enter())
        return 0;
    if (ksu_provenance_current_is_tagged() &&
        ksu_provenance_task_is_supervisor(child))
        error = -EPERM;
    ksu_provenance_hook_leave();
    return error;
}

static int ksu_provenance_ptrace_traceme(struct task_struct *parent)
{
    int error = 0;

    if (!ksu_provenance_hook_enter())
        return 0;
    if (ksu_provenance_current_is_tagged() &&
        ksu_provenance_task_is_supervisor(parent))
        error = -EPERM;
    ksu_provenance_hook_leave();
    return error;
}

static int ksu_provenance_task_kill(struct task_struct *task, struct kernel_siginfo *info,
                                    int sig, const struct cred *cred)
{
    int error = 0;

    if (!ksu_provenance_hook_enter())
        return 0;
    if (ksu_provenance_current_is_tagged() &&
        ksu_provenance_task_is_supervisor(task))
        error = -EPERM;
    ksu_provenance_hook_leave();
    return error;
}

static int ksu_provenance_file_receive(struct file *file)
{
    int error = 0;

    if (!ksu_provenance_hook_enter())
        return 0;
    if (ksu_provenance_is_control_file(file)) {
        ksu_provenance_note_descriptor_receive(file);
        error = -EPERM;
    }
    ksu_provenance_hook_leave();
    return error;
}

static struct ksu_lsm_hook ksu_provenance_bprm_hook =
    KSU_LSM_HOOK_APPEND_INIT(bprm_check_security, bprm_creds_for_exec,
                             "selinux_bprm_creds_for_exec", ksu_provenance_bprm_check_security);
static struct ksu_lsm_hook ksu_provenance_task_alloc_hook =
    KSU_LSM_HOOK_APPEND_INIT(task_alloc, task_alloc, "selinux_task_alloc",
                             ksu_provenance_task_alloc_callback);
static struct ksu_lsm_hook ksu_provenance_task_free_hook =
    KSU_LSM_HOOK_APPEND_INIT(task_free, task_alloc, "selinux_task_alloc",
                             ksu_provenance_task_free_callback);
static struct ksu_lsm_hook ksu_provenance_cred_alloc_blank_hook =
    KSU_LSM_HOOK_APPEND_INIT(cred_alloc_blank, cred_prepare, "selinux_cred_prepare",
                             ksu_provenance_cred_alloc_blank_callback);
static struct ksu_lsm_hook ksu_provenance_cred_prepare_hook =
    KSU_LSM_HOOK_APPEND_INIT(cred_prepare, cred_prepare, "selinux_cred_prepare",
                             ksu_provenance_cred_prepare_callback);
static struct ksu_lsm_hook ksu_provenance_cred_transfer_hook =
    KSU_LSM_HOOK_APPEND_INIT(cred_transfer, cred_transfer, "selinux_cred_transfer",
                             ksu_provenance_cred_transfer_callback);
static struct ksu_lsm_hook ksu_provenance_cred_free_hook =
    KSU_LSM_HOOK_APPEND_INIT(cred_free, cred_prepare, "selinux_cred_prepare",
                             ksu_provenance_cred_free_callback);
static struct ksu_lsm_hook ksu_provenance_ptrace_access_hook =
    KSU_LSM_HOOK_APPEND_INIT(ptrace_access_check, ptrace_access_check,
                             "selinux_ptrace_access_check", ksu_provenance_ptrace_access_check);
static struct ksu_lsm_hook ksu_provenance_ptrace_traceme_hook =
    KSU_LSM_HOOK_APPEND_INIT(ptrace_traceme, ptrace_traceme, "selinux_ptrace_traceme",
                             ksu_provenance_ptrace_traceme);
static struct ksu_lsm_hook ksu_provenance_task_kill_hook =
    KSU_LSM_HOOK_APPEND_INIT(task_kill, task_kill, "selinux_task_kill",
                             ksu_provenance_task_kill);
static struct ksu_lsm_hook ksu_provenance_file_receive_hook =
    KSU_LSM_HOOK_APPEND_INIT(file_receive, file_receive, "selinux_file_receive",
                             ksu_provenance_file_receive);

static struct ksu_lsm_hook *ksu_provenance_core_hooks[] = {
    &ksu_provenance_bprm_hook,
    &ksu_provenance_task_alloc_hook,
    &ksu_provenance_task_free_hook,
    &ksu_provenance_cred_alloc_blank_hook,
    &ksu_provenance_cred_prepare_hook,
    &ksu_provenance_cred_transfer_hook,
    &ksu_provenance_cred_free_hook,
    &ksu_provenance_ptrace_access_hook,
    &ksu_provenance_ptrace_traceme_hook,
    &ksu_provenance_task_kill_hook,
    &ksu_provenance_file_receive_hook,
};

static struct ksu_lsm_hook_group ksu_provenance_core_group = {
    .name = "CORE_CONTEXT_AND_ISOLATION",
    .hooks = ksu_provenance_core_hooks,
    .count = ARRAY_SIZE(ksu_provenance_core_hooks),
};

static u32 ksu_provenance_map_hook_error(int error, bool selftest)
{
    if (selftest && error == -EUCLEAN)
        return KSU_PROVENANCE_CORE_HOOK_SELFTEST;
    switch (error) {
    case -ENOENT:
        return KSU_PROVENANCE_CORE_HOOK_TARGET_ABSENT;
    case -ENOTUNIQ:
    case -EEXIST:
    case -EALREADY:
        return KSU_PROVENANCE_CORE_HOOK_TARGET_DUPLICATE;
    case -ESTALE:
        return KSU_PROVENANCE_CORE_HOOK_SLOT_CHANGED;
    case -EINVAL:
    case -EPROTO:
    case -ENOSPC:
        return KSU_PROVENANCE_CORE_HOOK_SLOT_UNEXPECTED;
    default:
        return KSU_PROVENANCE_CORE_HOOK_INSTALL;
    }
}

int ksu_provenance_provider_lsm_init(void)
{
    u32 verifier_state;
    u32 verifier_error;
    u64 minimum_epoch;
    u64 capabilities;
    u8 key_id[32];
    int error;

    ksu_provenance_image_verifier_diagnostics(&verifier_state, &verifier_error,
                                               &minimum_epoch, key_id, &capabilities);
    if (verifier_state != KSU_PROVENANCE_VERIFIER_READY) {
        ksu_provenance_core_hook_state = KSU_PROVENANCE_CORE_HOOK_FAILED;
        ksu_provenance_core_hook_error = KSU_PROVENANCE_CORE_HOOK_VERIFIER_NOT_READY;
        ksu_provenance_begin_drain();
        return -EKEYREJECTED;
    }

    WRITE_ONCE(ksu_provenance_hook_accepting, false);
    atomic_set(&ksu_provenance_hook_inflight, 0);
    error = ksu_lsm_hook_group_rollback_selftest(&ksu_provenance_core_group);
    if (error) {
        ksu_provenance_core_hook_state = KSU_PROVENANCE_CORE_HOOK_FAILED;
        ksu_provenance_core_hook_error = ksu_provenance_map_hook_error(error, true);
        ksu_provenance_begin_drain();
        return error;
    }
    error = ksu_lsm_hook_group_install(&ksu_provenance_core_group);
    if (error) {
        ksu_provenance_core_hook_state = KSU_PROVENANCE_CORE_HOOK_FAILED;
        ksu_provenance_core_hook_error = ksu_provenance_map_hook_error(error, false);
        ksu_provenance_begin_drain();
        return error;
    }
    smp_store_release(&ksu_provenance_hook_accepting, true);
    error = ksu_provenance_context_selftest();
    if (error) {
        smp_store_release(&ksu_provenance_hook_accepting, false);
        ksu_lsm_hook_group_uninstall(&ksu_provenance_core_group);
        ksu_provenance_core_hook_state = KSU_PROVENANCE_CORE_HOOK_FAILED;
        ksu_provenance_core_hook_error = KSU_PROVENANCE_CORE_HOOK_SELFTEST;
        ksu_provenance_begin_drain();
        return error;
    }
    ksu_provenance_core_hook_state = KSU_PROVENANCE_CORE_HOOK_INSTALLED;
    ksu_provenance_core_hook_error = KSU_PROVENANCE_CORE_HOOK_OK;
    return 0;
}

void ksu_provenance_provider_lsm_exit(void)
{
    int error;

    ksu_provenance_begin_drain();
    smp_store_release(&ksu_provenance_hook_accepting, false);
    error = ksu_lsm_hook_group_uninstall(&ksu_provenance_core_group);
    wait_event(ksu_provenance_hook_wait,
               atomic_read(&ksu_provenance_hook_inflight) == 0);

    if (error) {
        ksu_provenance_core_hook_state = KSU_PROVENANCE_CORE_HOOK_FAILED;
        ksu_provenance_core_hook_error = KSU_PROVENANCE_CORE_HOOK_ROLLBACK;
    } else if (ksu_provenance_core_hook_state == KSU_PROVENANCE_CORE_HOOK_INSTALLED) {
        ksu_provenance_core_hook_state = KSU_PROVENANCE_CORE_HOOK_RESTORED;
        ksu_provenance_core_hook_error = KSU_PROVENANCE_CORE_HOOK_OK;
    }
}

void ksu_provenance_provider_lsm_diagnostics(u32 *state, u32 *error,
                                              u64 *capabilities)
{
    *state = READ_ONCE(ksu_provenance_core_hook_state);
    *error = READ_ONCE(ksu_provenance_core_hook_error);
    *capabilities = 0;
    if (*state == KSU_PROVENANCE_CORE_HOOK_INSTALLED)
        *capabilities = KSU_PROVENANCE_CAP_CORE_HOOK_DIAGNOSTIC_V1 |
                        KSU_PROVENANCE_CAP_SIGNED_EXEC_ELIGIBILITY_V1;
}
