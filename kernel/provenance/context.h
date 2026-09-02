#ifndef __KSU_PROVENANCE_CONTEXT_H
#define __KSU_PROVENANCE_CONTEXT_H

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/types.h>

#include "provenance/image_verify.h"
#include "uapi/provenance.h"

int ksu_provenance_context_init(void);
void ksu_provenance_context_exit(void);
int ksu_provenance_context_selftest(void);

int ksu_provenance_claim_supervisor(
    const struct ksu_provenance_verified_image *image,
    u64 eligibility_generation,
    struct ksu_provenance_claim_result_v1 *result);
void ksu_provenance_fail_supervisor_claim(void);
int ksu_provenance_context_handle_control(
    struct ksu_provenance_control_cmd_v1 *command);

int ksu_provenance_task_alloc(struct task_struct *task);
void ksu_provenance_task_free(struct task_struct *task);
int ksu_provenance_cred_alloc_blank(struct cred *cred, gfp_t gfp);
int ksu_provenance_cred_prepare(struct cred *new, const struct cred *old,
                                gfp_t gfp);
void ksu_provenance_cred_transfer(struct cred *new, const struct cred *old);
void ksu_provenance_cred_free(struct cred *cred);

bool ksu_provenance_current_is_tagged(void);
bool ksu_provenance_task_is_supervisor(const struct task_struct *task);
bool ksu_provenance_current_is_supervisor(void);
bool ksu_provenance_is_control_file(const struct file *file);
void ksu_provenance_note_descriptor_receive(const struct file *file);
void ksu_provenance_note_task_exit(struct task_struct *task);

bool ksu_provenance_core_ready(void);
u64 ksu_provenance_operational_capabilities(void);
u32 ksu_provenance_supervisor_state(void);
u32 ksu_provenance_last_gap_reason(void);
void ksu_provenance_get_boot_epoch(u8 boot_epoch[16]);
void ksu_provenance_fill_context_status(
    struct ksu_provenance_context_status_v1 *status);
int ksu_provenance_fill_current_context(
    struct ksu_provenance_current_context_v1 *current_context);

void ksu_provenance_begin_drain(void);
bool ksu_provenance_can_unload(void);

#endif /* __KSU_PROVENANCE_CONTEXT_H */
