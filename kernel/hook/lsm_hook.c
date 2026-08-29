#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/string.h>

#include "infra/symbol_resolver.h"
#include "hook/lsm_hook.h"
#include "hook/patch_memory.h"
#include "klog.h" // IWYU pragma: keep
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include "linux/static_call.h"
#endif
static DEFINE_MUTEX(ksu_lsm_hook_lock);
static LIST_HEAD(ksu_lsm_hook_entries);
static size_t ksu_lsm_hook_count;

static bool ksu_lsm_hook_is_tracked(struct ksu_lsm_hook *hook)
{
    return hook && hook->tracked;
}

static int ksu_lsm_hook_track(struct ksu_lsm_hook *hook)
{
    if (ksu_lsm_hook_is_tracked(hook))
        return 0;

    INIT_LIST_HEAD(&hook->registry_node);
    list_add_tail(&hook->registry_node, &ksu_lsm_hook_entries);
    hook->tracked = true;
    ksu_lsm_hook_count++;
    return 0;
}

static void ksu_lsm_hook_untrack(struct ksu_lsm_hook *hook)
{
    if (!ksu_lsm_hook_is_tracked(hook))
        return;
    list_del_init(&hook->registry_node);
    hook->tracked = false;
    ksu_lsm_hook_count--;
}

static void *ksu_lsm_hook_unwrap_original(void *hook_fn)
{
    struct ksu_lsm_hook *tracked;

    list_for_each_entry (tracked, &ksu_lsm_hook_entries, registry_node) {
        if (tracked->replacement == hook_fn)
            return tracked->original;
    }
    return hook_fn;
}

static int ksu_lsm_hook_patch_slot(void **slot, void *value)
{
    void *patched = value;
    int ret;

    ret = ksu_patch_text(slot, &patched, sizeof(patched), KSU_PATCH_TEXT_FLUSH_DCACHE);
    if (!ret)
        smp_wmb();

    return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
typedef void (*ksu_static_call_update_t)(struct static_call_key *key, void *tramp, void *func);

static int ksu_lsm_hook_update_scall(struct lsm_static_call *scall, void *value)
{
    __static_call_update(scall->key, scall->trampoline, value);
    smp_wmb();
    return 0;
}
#endif

int ksu_lsm_hook(struct ksu_lsm_hook *hook)
{
    int ret = 0;
    struct security_hook_list *entry;
    void *target;
    const char *target_name;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    static unsigned long scalls_addr = 0;
    struct lsm_static_call *scalls = NULL;
    static size_t scalls_count = 0;
    static u32 lsm_max_cnt = 5;
    struct security_hook_list *selected_entry = NULL;
    struct lsm_static_call *selected_scall = NULL;
    void **selected_slot = NULL;
    void *selected_origin = NULL;
    size_t i;
#else
    unsigned long heads_addr;
    struct hlist_head *head;
    struct security_hook_list *selected_entry = NULL;
    void **selected_slot = NULL;
    void *selected_origin = NULL;
#endif

    if (!hook || !hook->replacement)
        return -EINVAL;

    mutex_lock(&ksu_lsm_hook_lock);

    if (hook->entry) {
        ret = -EALREADY;
        goto out_unlock;
    }

    target_name = hook->target_name;
    if (!target_name) {
        pr_err("lsm_hook: hook %s: target_name is required\n", hook->head_name ?: "unknown");
        ret = -EINVAL;
        goto out_unlock;
    }

    target = hook->original;
    if (!target)
        target = ksu_resolve_symbol_for_functable_hook(target_name);
    if (!target) {
        pr_err("lsm_hook: failed to resolve target for %s\n", hook->head_name ?: "unknown");
        ret = -ENOENT;
        goto out_unlock;
    }
    pr_info("target: 0x%lx %pSb\n", (unsigned long)target, target);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    if (!scalls_addr) {
        scalls_addr = find_kernel_symbol_exact("static_calls_table");
    }
    if (!scalls_addr) {
        pr_err("lsm_hook: failed to resolve static_calls_table\n");
        ret = -ENOSYS;
        goto out_unlock;
    }

    if (scalls_count == 0) {
        unsigned long sym_size = sizeof(struct lsm_static_calls_table);
        u32 lsm_active_cnt = 5;
        if (!kallsyms_lookup_size_offset(scalls_addr, &sym_size, NULL)) {
            pr_err("failed to get size\n");
        }
        unsigned long addr = find_kernel_symbol_exact("lsm_active_cnt");
        if (!addr) {
            pr_err("failed to get lsm_active_cnt\n");
        } else {
            lsm_active_cnt = *(u32 *)addr;
        }
        pr_info("lsm_active_cnt = %d\n", lsm_active_cnt);
        if (lsm_active_cnt == 0 || lsm_active_cnt > 20) {
            pr_err("invalid lsm_active_cnt\n");
        } else {
            lsm_max_cnt = lsm_active_cnt;
            if (sym_size % (lsm_active_cnt * sizeof(struct lsm_static_call)) != 0) {
                pr_warn("invalid struct size\n");
            }
            scalls_count = sym_size / sizeof(struct lsm_static_call);
            pr_info("scalls_count = %zu\n", scalls_count);
        }
    }

    if (scalls_count == 0) {
        pr_err("no scalls_count found!\n");
        ret = -ENOSYS;
        goto out_unlock;
    }

    scalls = (struct lsm_static_call *)scalls_addr;
    for (i = 0; i < scalls_count; i++) {
        struct lsm_static_call *scall = &scalls[i];
        void **slot;
        void *current_origin;

        entry = READ_ONCE(scall->hl);
        if (!entry)
            continue;

        slot = (void **)((char *)entry + hook->hook_offset);
        current_origin = READ_ONCE(*slot);

        current_origin = ksu_lsm_hook_unwrap_original(current_origin);

        if (current_origin == hook->replacement) {
            ret = -EALREADY;
            goto out_unlock;
        }

        if (current_origin != target) {
            continue;
        }

        pr_info("found slot %ld orig %pSb\n", i, current_origin);

        if (!hook->offset) {
            selected_entry = entry;
            selected_scall = scall;
            selected_slot = slot;
            selected_origin = current_origin;
        } else {
            size_t hook_idx = (i / lsm_max_cnt + hook->offset) * lsm_max_cnt;
            if (hook_idx >= scalls_count) {
                pr_err("last lsm hook reached\n");
                ret = -EINVAL;
                goto out_unlock;
            }
            scall = &scalls[hook_idx];
            entry = READ_ONCE(scall->hl);
            if (entry) {
                slot = (void **)((char *)entry + hook->hook_offset);
                current_origin = READ_ONCE(*slot);
            } else {
                current_origin = NULL;
            }
            pr_info("found real slot %ld orig %pSb\n", i, current_origin);

            if (current_origin == hook->replacement) {
                ret = -EALREADY;
                goto out_unlock;
            }
            selected_entry = entry;
            selected_scall = scall;
            selected_slot = slot;
            selected_origin = current_origin;
        }
        break;
    }

    if (!selected_scall) {
        pr_err("lsm_hook: target %s not found in head %s\n", target_name, hook->head_name ?: "unknown");
        ret = -ENOENT;
        goto out_unlock;
    }

    ret = ksu_lsm_hook_track(hook);
    if (ret) {
        pr_err("lsm_hook: too many hooks to track: %d\n", ret);
        goto out_unlock;
    }

    if (ksu_lsm_hook_patch_slot(selected_slot, hook->replacement)) {
        pr_err("lsm_hook: failed to patch %s\n", hook->head_name ?: "unknown");
        ret = -EFAULT;
        goto out_untrack;
    }

    if (ksu_lsm_hook_update_scall(selected_scall, hook->replacement)) {
        if (ksu_lsm_hook_patch_slot(selected_slot, selected_origin)) {
            pr_err("lsm_hook: failed to roll back %s after static call update failure\n", hook->head_name ?: "unknown");
        }
        ret = -EFAULT;
        goto out_untrack;
    }

    if (!selected_origin)
        static_branch_enable(selected_scall->active);

    hook->entry = selected_entry;
    hook->scall = selected_scall;
    hook->original = selected_origin;
    pr_info("lsm_hook: patched %s hook slot %px from %px to %px\n", hook->head_name ?: "unknown", selected_slot,
            selected_origin, hook->replacement);
#else
    heads_addr = find_kernel_symbol_exact("security_hook_heads");
    if (!heads_addr) {
        pr_err("lsm_hook: failed to resolve security_hook_heads\n");
        ret = -ENOENT;
        goto out_unlock;
    }
    unsigned long heads_size = sizeof(struct security_hook_heads);
    if (!kallsyms_lookup_size_offset(heads_addr, &heads_size, NULL)) {
        pr_warn("lookup head size failed");
    }

    head = (struct hlist_head *)heads_addr;
    struct hlist_head *head_end = (struct hlist_head *)(heads_addr + heads_size);
    pr_info("heads_addr 0x%lx head_offset 0x%lx heads_size %ld hook_offset 0x%lx\n", (unsigned long)heads_addr,
            hook->head_offset, heads_size, hook->hook_offset);

    for (; head < head_end; head++) {
        hlist_for_each_entry (entry, head, list) {
            void **slot = (void **)((char *)entry + hook->hook_offset);
            void *current_origin = READ_ONCE(*slot);
            current_origin = ksu_lsm_hook_unwrap_original(current_origin);
            if (current_origin == hook->replacement) {
                ret = -EALREADY;
                goto out_unlock;
            }
            if (current_origin == target) {
                pr_info("found %s (target %s) at head offset %ld (provided %ld)\n", hook->head_name, hook->target_name,
                        (unsigned long)head - heads_addr, hook->head_offset);
                selected_entry = entry;
                selected_slot = slot;
                selected_origin = current_origin;
                break;
            }
        }
        if (selected_entry) {
            if (hook->offset) {
                head += hook->offset;
                if (head < (struct hlist_head *)heads_addr || head >= head_end) {
                    pr_err("invalid offset\n");
                    ret = -EINVAL;
                    goto out_unlock;
                }
                // just check if already hooked
                hlist_for_each_entry (entry, head, list) {
                    void **slot = (void **)((char *)entry + hook->hook_offset);
                    void *current_origin = READ_ONCE(*slot);
                    if (current_origin == hook->replacement) {
                        ret = -EALREADY;
                        goto out_unlock;
                    }
                }
                if (head->first) {
                    selected_entry = hlist_entry(head->first, struct security_hook_list, list);
                    selected_slot = (void **)((char *)selected_entry + hook->hook_offset);
                    selected_origin = *selected_slot;
                } else {
                    selected_entry = &hook->list;
                    hook->list.head = head;
                    hook->list.list.next = NULL;
                    hook->list.list.pprev = &head->first;
                    hook->list.lsm = "ksu";
                    *(void **)((char *)selected_entry + hook->hook_offset) = hook->replacement;
                    selected_slot = (void **)&head->first;
                    selected_origin = NULL;
                }
            }
            break;
        }
    }

    if (!selected_entry) {
        pr_err("lsm_hook: target %s not found in head %s\n", target_name, hook->head_name ?: "unknown");
        ret = -ENOENT;
        goto out_unlock;
    }

    ret = ksu_lsm_hook_track(hook);
    if (ret) {
        pr_err("lsm_hook: too many hooks to track: %d\n", ret);
        goto out_unlock;
    }

    if (selected_origin) {
        pr_info("patch func addr\n");
        ret = ksu_lsm_hook_patch_slot(selected_slot, hook->replacement);
    } else {
        pr_info("patch head->first\n");
        ret = ksu_lsm_hook_patch_slot(selected_slot, &hook->list);
    }

    if (ret) {
        pr_err("lsm_hook: failed to patch %s\n", hook->head_name ?: "unknown");
        ret = -EFAULT;
        goto out_untrack;
    }

    hook->entry = selected_entry;
    hook->original = selected_origin;
    pr_info("lsm_hook: patched %s hook slot %px from %px to %px\n", hook->head_name ?: "unknown", selected_slot,
            selected_origin, hook->replacement);
#endif
    goto out_unlock;
out_untrack:
    ksu_lsm_hook_untrack(hook);

out_unlock:
    mutex_unlock(&ksu_lsm_hook_lock);
    return ret;
}

void ksu_lsm_unhook(struct ksu_lsm_hook *hook)
{
    void **slot;
    mutex_lock(&ksu_lsm_hook_lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    if (!hook->entry || !hook->scall) {
#else
    if (!hook->entry) {
#endif
        mutex_unlock(&ksu_lsm_hook_lock);
        return;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    slot = (void **)((char *)hook->entry + hook->hook_offset);
#else
    if (hook->entry == &hook->list) {
        slot = (void **)&hook->list.head->first;
        pr_info("unhook patch head->first\n");
    } else {
        slot = (void **)((char *)hook->entry + hook->hook_offset);
        pr_info("unhook patch slot\n");
    }
#endif
    if (ksu_lsm_hook_patch_slot(slot, hook->original)) {
        pr_err("lsm_hook: failed to restore %s\n", hook->head_name ?: "unknown");
        mutex_unlock(&ksu_lsm_hook_lock);
        return;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    if (ksu_lsm_hook_update_scall(hook->scall, hook->original)) {
        if (ksu_lsm_hook_patch_slot(slot, hook->replacement))
            pr_err("lsm_hook: failed to reapply %s after static call restore failure\n", hook->head_name ?: "unknown");
        mutex_unlock(&ksu_lsm_hook_lock);
        return;
    }
#endif

    synchronize_rcu();
    pr_info("lsm_hook: restored %s hook slot %px to %px\n", hook->head_name ?: "unknown", slot, hook->original);
    ksu_lsm_hook_untrack(hook);
    hook->entry = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    hook->scall = NULL;
#endif
    mutex_unlock(&ksu_lsm_hook_lock);
}

int ksu_register_lsm_hook(struct ksu_lsm_hook *hook)
{
    return ksu_lsm_hook(hook);
}

void ksu_unregister_lsm_hook(struct ksu_lsm_hook *hook)
{
    ksu_lsm_unhook(hook);
}

static int ksu_lsm_append_resolve_locked(struct ksu_lsm_hook *hook)
{
    void *anchor_target;
    unsigned long heads_addr;
    unsigned long heads_size;
    int anchor_matches = 0;

    if (!hook || !hook->appended || !hook->replacement || !hook->anchor_target_name)
        return -EINVAL;
    if (hook->tracked || hook->entry || hook->patched_slot)
        return -EALREADY;

    anchor_target = ksu_resolve_symbol_for_functable_hook(hook->anchor_target_name);
    if (!anchor_target) {
        pr_err("lsm_hook: group anchor %s is absent for %s\n", hook->anchor_target_name,
               hook->head_name ?: "unknown");
        return -ENOENT;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    {
        struct lsm_static_call *anchor_scalls = NULL;
        struct lsm_static_call *target_scalls;
        struct lsm_static_call *free_scall = NULL;
        const size_t head_size = sizeof(*anchor_scalls) * MAX_LSM_COUNT;
        long target_offset;
        size_t i;
        size_t head_offset;

        heads_addr = find_kernel_symbol_exact("static_calls_table");
        if (!heads_addr)
            return -ENOENT;
        heads_size = sizeof(struct lsm_static_calls_table);
        if (!kallsyms_lookup_size_offset(heads_addr, &heads_size, NULL) ||
            heads_size != sizeof(struct lsm_static_calls_table) || heads_size % head_size)
            return -EPROTO;

        for (head_offset = 0; head_offset < heads_size; head_offset += head_size) {
            struct lsm_static_call *candidate =
                (struct lsm_static_call *)(heads_addr + head_offset);

            for (i = 0; i < MAX_LSM_COUNT; i++) {
                struct security_hook_list *entry = READ_ONCE(candidate[i].hl);
                void *hook_fn;

                if (!entry)
                    continue;
                hook_fn = READ_ONCE(*(void **)((char *)entry + hook->anchor_hook_offset));
                if (ksu_lsm_hook_unwrap_original(hook_fn) == anchor_target) {
                    anchor_matches++;
                    anchor_scalls = candidate;
                }
            }
        }
        if (anchor_matches != 1) {
            pr_err("lsm_hook: anchor %s matched %d slots for %s\n", hook->anchor_target_name,
                   anchor_matches, hook->head_name ?: "unknown");
            return anchor_matches ? -ENOTUNIQ : -ENOENT;
        }
        if ((char *)anchor_scalls != (char *)heads_addr + hook->anchor_head_offset)
            return -EPROTO;
        target_offset = (char *)anchor_scalls - (char *)heads_addr + hook->target_head_delta;
        if (target_offset < 0 || (unsigned long)target_offset > heads_size - head_size ||
            (unsigned long)target_offset % head_size ||
            (unsigned long)target_offset != hook->head_offset)
            return -EPROTO;
        target_scalls = (struct lsm_static_call *)(heads_addr + target_offset);

        for (i = 0; i < MAX_LSM_COUNT; i++) {
            struct security_hook_list *entry = READ_ONCE(target_scalls[i].hl);
            void *hook_fn;

            if (!entry) {
                if (!free_scall)
                    free_scall = &target_scalls[i];
                continue;
            }
            hook_fn = READ_ONCE(*(void **)((char *)entry + hook->hook_offset));
            if (hook_fn == hook->replacement)
                return -EEXIST;
        }
        if (!free_scall) {
            pr_err("lsm_hook: no free static-call slot for %s\n", hook->head_name ?: "unknown");
            return -ENOSPC;
        }
        memset(&hook->list, 0, sizeof(hook->list));
        hook->list.scalls = target_scalls;
        *(void **)((char *)&hook->list + hook->hook_offset) = hook->replacement;
        hook->scall = free_scall;
        hook->patched_slot = (void **)&free_scall->hl;
        hook->patched_value = &hook->list;
    }
#else
    {
        struct hlist_head *anchor_head = NULL;
        struct hlist_head *target_head;
        struct security_hook_list *entry;
        void **tail_slot;
        long target_offset;
        size_t head_offset;

        heads_addr = find_kernel_symbol_exact("security_hook_heads");
        if (!heads_addr)
            return -ENOENT;
        heads_size = sizeof(struct security_hook_heads);
        if (!kallsyms_lookup_size_offset(heads_addr, &heads_size, NULL) ||
            heads_size != sizeof(struct security_hook_heads) ||
            heads_size % sizeof(struct hlist_head))
            return -EPROTO;

        for (head_offset = 0; head_offset < heads_size;
             head_offset += sizeof(struct hlist_head)) {
            struct hlist_head *candidate =
                (struct hlist_head *)(heads_addr + head_offset);

            hlist_for_each_entry (entry, candidate, list) {
                void *hook_fn = READ_ONCE(*(void **)((char *)entry + hook->anchor_hook_offset));

                if (ksu_lsm_hook_unwrap_original(hook_fn) == anchor_target) {
                    anchor_matches++;
                    anchor_head = candidate;
                }
            }
        }
        if (anchor_matches != 1) {
            pr_err("lsm_hook: anchor %s matched %d slots for %s\n", hook->anchor_target_name,
                   anchor_matches, hook->head_name ?: "unknown");
            return anchor_matches ? -ENOTUNIQ : -ENOENT;
        }
        if ((char *)anchor_head != (char *)heads_addr + hook->anchor_head_offset)
            return -EPROTO;
        target_offset = (char *)anchor_head - (char *)heads_addr + hook->target_head_delta;
        if (target_offset < 0 ||
            (unsigned long)target_offset > heads_size - sizeof(*target_head) ||
            (unsigned long)target_offset % sizeof(*target_head) ||
            (unsigned long)target_offset != hook->head_offset)
            return -EPROTO;
        target_head = (struct hlist_head *)(heads_addr + target_offset);

        tail_slot = (void **)&target_head->first;
        hlist_for_each_entry (entry, target_head, list) {
            void *hook_fn = READ_ONCE(*(void **)((char *)entry + hook->hook_offset));

            if (hook_fn == hook->replacement)
                return -EEXIST;
            tail_slot = (void **)&entry->list.next;
        }
        if (READ_ONCE(*tail_slot))
            return -ESTALE;

        memset(&hook->list, 0, sizeof(hook->list));
        hook->list.head = target_head;
        hook->list.list.pprev = (struct hlist_node **)tail_slot;
        hook->list.lsm = "ksu";
        *(void **)((char *)&hook->list + hook->hook_offset) = hook->replacement;
        hook->patched_slot = tail_slot;
        hook->patched_value = &hook->list.list;
    }
#endif
    return 0;
}

static void ksu_lsm_append_clear_resolution(struct ksu_lsm_hook *hook)
{
    hook->patched_slot = NULL;
    hook->patched_value = NULL;
    hook->entry = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    hook->scall = NULL;
#endif
}

static int ksu_lsm_append_install_locked(struct ksu_lsm_hook *hook)
{
    int error;

    if (!hook->patched_slot || READ_ONCE(*hook->patched_slot) != NULL)
        return -ESTALE;

    error = ksu_lsm_hook_patch_slot(hook->patched_slot, hook->patched_value);
    if (error)
        return error;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    error = ksu_lsm_hook_update_scall(hook->scall, hook->replacement);
    if (error) {
        ksu_lsm_hook_patch_slot(hook->patched_slot, NULL);
        return error;
    }
    static_branch_enable(hook->scall->active);
#endif
    hook->entry = &hook->list;
    error = ksu_lsm_hook_track(hook);
    if (error)
        return error;
    return 0;
}

static int ksu_lsm_append_uninstall_locked(struct ksu_lsm_hook *hook)
{
    int error;

    if (!hook->tracked || !hook->patched_slot || READ_ONCE(*hook->patched_slot) != hook->patched_value)
        return -ESTALE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    static_branch_disable(hook->scall->active);
    error = ksu_lsm_hook_update_scall(hook->scall, NULL);
    if (error) {
        static_branch_enable(hook->scall->active);
        return error;
    }
#endif
    error = ksu_lsm_hook_patch_slot(hook->patched_slot, NULL);
    if (error) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
        ksu_lsm_hook_update_scall(hook->scall, hook->replacement);
        static_branch_enable(hook->scall->active);
#endif
        return error;
    }
    ksu_lsm_hook_untrack(hook);
    ksu_lsm_append_clear_resolution(hook);
    return 0;
}

static int ksu_lsm_append_validate_installed_locked(struct ksu_lsm_hook *hook)
{
    if (!hook->tracked || !hook->entry || !hook->patched_slot ||
        READ_ONCE(*hook->patched_slot) != hook->patched_value)
        return -ESTALE;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    if (!hook->scall || READ_ONCE(hook->scall->hl) != &hook->list)
        return -ESTALE;
#else
    if (READ_ONCE(hook->list.list.next))
        return -ESTALE;
#endif
    return 0;
}

static int ksu_lsm_hook_group_resolve_locked(struct ksu_lsm_hook_group *group)
{
    size_t i;
    size_t j;
    int error;

    if (!group || !group->hooks || !group->count || group->installed)
        return -EINVAL;
    for (i = 0; i < group->count; i++) {
        error = ksu_lsm_append_resolve_locked(group->hooks[i]);
        if (error)
            goto clear;
        for (j = 0; j < i; j++) {
            if (group->hooks[j]->patched_slot == group->hooks[i]->patched_slot) {
                error = -EEXIST;
                ksu_lsm_append_clear_resolution(group->hooks[i]);
                goto clear;
            }
        }
    }
    return 0;

clear:
    while (i > 0)
        ksu_lsm_append_clear_resolution(group->hooks[--i]);
    return error;
}

static int ksu_lsm_hook_group_install_locked(struct ksu_lsm_hook_group *group, size_t fail_at)
{
    size_t installed = 0;
    int error;
    int rollback_error = 0;

    error = ksu_lsm_hook_group_resolve_locked(group);
    if (error)
        return error;
    for (installed = 0; installed < group->count; installed++) {
        if (installed == fail_at) {
            error = -EINTR;
            goto rollback;
        }
        error = ksu_lsm_append_install_locked(group->hooks[installed]);
        if (error)
            goto rollback;
    }
    if (installed == fail_at) {
        error = -EINTR;
        goto rollback;
    }
    group->installed = true;
    return 0;

rollback:
    while (installed > 0) {
        int uninstall_error = ksu_lsm_append_uninstall_locked(group->hooks[--installed]);

        if (uninstall_error && !rollback_error)
            rollback_error = uninstall_error;
    }
    while (installed < group->count)
        ksu_lsm_append_clear_resolution(group->hooks[installed++]);
    return rollback_error ?: error;
}

int ksu_lsm_hook_group_install(struct ksu_lsm_hook_group *group)
{
    int error;

    mutex_lock(&ksu_lsm_hook_lock);
    error = ksu_lsm_hook_group_install_locked(group, SIZE_MAX);
    mutex_unlock(&ksu_lsm_hook_lock);
    if (!error)
        synchronize_rcu();
    return error;
}

int ksu_lsm_hook_group_uninstall(struct ksu_lsm_hook_group *group)
{
    size_t index;
    int error = 0;

    if (!group)
        return -EINVAL;
    mutex_lock(&ksu_lsm_hook_lock);
    if (!group->installed) {
        mutex_unlock(&ksu_lsm_hook_lock);
        return 0;
    }
    for (index = 0; index < group->count; index++) {
        error = ksu_lsm_append_validate_installed_locked(group->hooks[index]);
        if (error) {
            mutex_unlock(&ksu_lsm_hook_lock);
            return error;
        }
    }
    for (index = group->count; index > 0; index--) {
        int uninstall_error = ksu_lsm_append_uninstall_locked(group->hooks[index - 1]);

        if (uninstall_error && !error)
            error = uninstall_error;
    }
    if (!error)
        group->installed = false;
    mutex_unlock(&ksu_lsm_hook_lock);
    synchronize_rcu();
    return error;
}

int ksu_lsm_hook_group_rollback_selftest(struct ksu_lsm_hook_group *group)
{
    size_t fail_at;
    int error = 0;

    if (!group)
        return -EINVAL;
    mutex_lock(&ksu_lsm_hook_lock);
    for (fail_at = 0; fail_at <= group->count; fail_at++) {
        int install_error = ksu_lsm_hook_group_install_locked(group, fail_at);

        if (install_error != -EINTR) {
            error = install_error ?: -EUCLEAN;
            break;
        }
    }
    mutex_unlock(&ksu_lsm_hook_lock);
    synchronize_rcu();
    return error;
}

void __init ksu_lsm_hook_init(void)
{
    pr_info("lsm_hook: init, tracked hooks=%zu\n", READ_ONCE(ksu_lsm_hook_count));
}

void __exit ksu_lsm_hook_exit(void)
{
    for (;;) {
        struct ksu_lsm_hook *hook;

        mutex_lock(&ksu_lsm_hook_lock);
        if (list_empty(&ksu_lsm_hook_entries)) {
            mutex_unlock(&ksu_lsm_hook_lock);
            break;
        }
        hook = list_last_entry(&ksu_lsm_hook_entries, struct ksu_lsm_hook, registry_node);
        mutex_unlock(&ksu_lsm_hook_lock);
        if (hook->appended) {
            struct ksu_lsm_hook_group single = {
                .name = hook->head_name,
                .hooks = &hook,
                .count = 1,
                .installed = true,
            };
            ksu_lsm_hook_group_uninstall(&single);
        } else {
            ksu_lsm_unhook(hook);
        }
    }
}
