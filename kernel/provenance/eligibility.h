#ifndef __KSU_PROVENANCE_ELIGIBILITY_H
#define __KSU_PROVENANCE_ELIGIBILITY_H

#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>

#include "uapi/provenance.h"

#ifdef CONFIG_KSU_PROVENANCE
int ksu_provenance_eligibility_init(void);
void ksu_provenance_eligibility_exit(void);
void ksu_provenance_consider_exec(struct linux_binprm *bprm);
void ksu_provenance_note_post_fs_data(struct task_struct *task);
void ksu_provenance_get_eligibility_info(struct ksu_provenance_eligibility_info_v1 *info);
int ksu_provenance_handle_control(struct ksu_provenance_control_cmd_v1 *command);
#else
static inline void ksu_provenance_note_post_fs_data(struct task_struct *task)
{
}

static inline void ksu_provenance_get_eligibility_info(struct ksu_provenance_eligibility_info_v1 *info)
{
    memset(info, 0, sizeof(*info));
    info->size = sizeof(*info);
    info->version = KSU_PROVENANCE_UAPI_VERSION;
    info->core_hook_state = KSU_PROVENANCE_CORE_HOOK_DISABLED;
    info->core_hook_error = KSU_PROVENANCE_CORE_HOOK_NOT_CONFIGURED;
}

static inline int ksu_provenance_handle_control(struct ksu_provenance_control_cmd_v1 *command)
{
    return -EOPNOTSUPP;
}
#endif

#endif /* __KSU_PROVENANCE_ELIGIBILITY_H */
