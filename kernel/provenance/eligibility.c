#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "ksu.h"
#include "provenance/eligibility.h"
#include "provenance/image_verify.h"
#include "provenance/provider_lsm.h"
#include "runtime/ksud.h"
#include "uapi/provenance.h"

#define KSU_PROVENANCE_SIDECAR_PATH KSUD_PATH ".provenance"

static DEFINE_MUTEX(ksu_provenance_eligibility_lock);
static struct task_struct *ksu_provenance_candidate_task;
static struct ksu_provenance_verified_image ksu_provenance_candidate_image;
static u32 ksu_provenance_eligibility_state = KSU_PROVENANCE_ELIGIBILITY_NONE;
static u32 ksu_provenance_eligibility_error = KSU_PROVENANCE_ELIGIBILITY_OK;
static u64 ksu_provenance_eligibility_generation;
static bool ksu_provenance_post_fs_data_seen;

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

static bool ksu_provenance_is_ksud_exec_file(struct file *file)
{
    struct path expected;
    bool matches;

    if (!file || kern_path(KSUD_PATH, LOOKUP_FOLLOW, &expected))
        return false;
    matches = path_equal(&file->f_path, &expected);
    path_put(&expected);
    return matches;
}

static bool ksu_provenance_is_init_child(struct task_struct *task)
{
    struct task_struct *parent;
    bool matches;

    rcu_read_lock();
    parent = rcu_dereference(task->real_parent);
    matches = parent && is_global_init(parent);
    rcu_read_unlock();
    return matches;
}

static u32 ksu_provenance_map_eligibility_error(u32 verifier_error)
{
    switch (verifier_error) {
    case KSU_PROVENANCE_VERIFY_ROLE:
        return KSU_PROVENANCE_ELIGIBILITY_ROLE;
    case KSU_PROVENANCE_VERIFY_UAPI:
        return KSU_PROVENANCE_ELIGIBILITY_UAPI;
    case KSU_PROVENANCE_VERIFY_EPOCH:
        return KSU_PROVENANCE_ELIGIBILITY_EPOCH;
    default:
        return KSU_PROVENANCE_ELIGIBILITY_IMAGE;
    }
}

static bool ksu_provenance_has_candidate_locked(void)
{
    return ksu_provenance_eligibility_state == KSU_PROVENANCE_ELIGIBILITY_PENDING_STAGE ||
           ksu_provenance_eligibility_state == KSU_PROVENANCE_ELIGIBILITY_ELIGIBLE;
}

static void ksu_provenance_clear_candidate_locked(void)
{
    if (ksu_provenance_candidate_task)
        put_task_struct(ksu_provenance_candidate_task);
    ksu_provenance_candidate_task = NULL;
    memset(&ksu_provenance_candidate_image, 0, sizeof(ksu_provenance_candidate_image));
}

static void ksu_provenance_record_rejection_locked(
    const struct ksu_provenance_verified_image *image, u32 error)
{
    if (ksu_provenance_has_candidate_locked())
        return;
    if (ksu_provenance_post_fs_data_seen &&
        ksu_provenance_eligibility_state == KSU_PROVENANCE_ELIGIBILITY_REJECTED)
        return;

    ksu_provenance_clear_candidate_locked();
    if (image)
        ksu_provenance_candidate_image = *image;
    ksu_provenance_eligibility_state = KSU_PROVENANCE_ELIGIBILITY_REJECTED;
    ksu_provenance_eligibility_error = error;
}

static void ksu_provenance_record_candidate_locked(
    struct task_struct *task, const struct ksu_provenance_verified_image *image)
{
    if (ksu_provenance_has_candidate_locked() || ksu_provenance_post_fs_data_seen)
        return;

    ksu_provenance_clear_candidate_locked();
    ksu_provenance_candidate_task = task;
    get_task_struct(task);
    ksu_provenance_candidate_image = *image;
    ksu_provenance_eligibility_generation++;
    if (!ksu_provenance_eligibility_generation)
        ksu_provenance_eligibility_generation = 1;
    ksu_provenance_eligibility_state = KSU_PROVENANCE_ELIGIBILITY_PENDING_STAGE;
    ksu_provenance_eligibility_error = KSU_PROVENANCE_ELIGIBILITY_OK;
}

int ksu_provenance_eligibility_init(void)
{
    mutex_lock(&ksu_provenance_eligibility_lock);
    ksu_provenance_clear_candidate_locked();
    ksu_provenance_eligibility_state = KSU_PROVENANCE_ELIGIBILITY_NONE;
    ksu_provenance_eligibility_error = KSU_PROVENANCE_ELIGIBILITY_OK;
    ksu_provenance_eligibility_generation = 0;
    ksu_provenance_post_fs_data_seen = false;
    mutex_unlock(&ksu_provenance_eligibility_lock);
    return 0;
}

void ksu_provenance_eligibility_exit(void)
{
    mutex_lock(&ksu_provenance_eligibility_lock);
    if (ksu_provenance_candidate_task)
        put_task_struct(ksu_provenance_candidate_task);
    ksu_provenance_candidate_task = NULL;
    memset(&ksu_provenance_candidate_image, 0, sizeof(ksu_provenance_candidate_image));
    ksu_provenance_eligibility_state = KSU_PROVENANCE_ELIGIBILITY_NONE;
    ksu_provenance_eligibility_error = KSU_PROVENANCE_ELIGIBILITY_OK;
    ksu_provenance_eligibility_generation = 0;
    ksu_provenance_post_fs_data_seen = false;
    mutex_unlock(&ksu_provenance_eligibility_lock);
}

void ksu_provenance_consider_exec(struct linux_binprm *bprm)
{
    struct ksu_provenance_verified_image verified = { 0 };
    int error;

    if (!bprm || !ksu_provenance_is_ksud_exec_file(bprm->file))
        return;

    if (ksu_late_loaded) {
        mutex_lock(&ksu_provenance_eligibility_lock);
        ksu_provenance_record_rejection_locked(NULL, KSU_PROVENANCE_ELIGIBILITY_LATE_LOAD);
        mutex_unlock(&ksu_provenance_eligibility_lock);
        return;
    }

    mutex_lock(&ksu_provenance_eligibility_lock);
    if (ksu_provenance_has_candidate_locked()) {
        mutex_unlock(&ksu_provenance_eligibility_lock);
        return;
    }
    if (ksu_provenance_post_fs_data_seen) {
        ksu_provenance_record_rejection_locked(NULL,
                                                KSU_PROVENANCE_ELIGIBILITY_WRONG_BOOT_STAGE);
        mutex_unlock(&ksu_provenance_eligibility_lock);
        return;
    }
    mutex_unlock(&ksu_provenance_eligibility_lock);

    if (!ksu_provenance_is_init_child(current)) {
        mutex_lock(&ksu_provenance_eligibility_lock);
        ksu_provenance_record_rejection_locked(NULL, KSU_PROVENANCE_ELIGIBILITY_WRONG_PARENT);
        mutex_unlock(&ksu_provenance_eligibility_lock);
        return;
    }

    error = ksu_provenance_verify_image(bprm->file, KSU_PROVENANCE_SIDECAR_PATH,
                                        KSU_PROVENANCE_ROLE_SUPERVISOR, &verified);
    mutex_lock(&ksu_provenance_eligibility_lock);
    if (error) {
        ksu_provenance_record_rejection_locked(
            &verified, ksu_provenance_map_eligibility_error(verified.error));
    } else {
        ksu_provenance_record_candidate_locked(current, &verified);
    }
    mutex_unlock(&ksu_provenance_eligibility_lock);
}

void ksu_provenance_note_post_fs_data(struct task_struct *task)
{
    mutex_lock(&ksu_provenance_eligibility_lock);
    ksu_provenance_post_fs_data_seen = true;
    if (ksu_provenance_eligibility_state == KSU_PROVENANCE_ELIGIBILITY_PENDING_STAGE &&
        ksu_provenance_candidate_task == task) {
        ksu_provenance_eligibility_state = KSU_PROVENANCE_ELIGIBILITY_ELIGIBLE;
        ksu_provenance_eligibility_error = KSU_PROVENANCE_ELIGIBILITY_OK;
    } else if (ksu_provenance_eligibility_state ==
               KSU_PROVENANCE_ELIGIBILITY_PENDING_STAGE) {
        if (ksu_provenance_candidate_task)
            put_task_struct(ksu_provenance_candidate_task);
        ksu_provenance_candidate_task = NULL;
        ksu_provenance_eligibility_state = KSU_PROVENANCE_ELIGIBILITY_REJECTED;
        ksu_provenance_eligibility_error =
            KSU_PROVENANCE_ELIGIBILITY_WRONG_BOOT_STAGE;
    } else if (ksu_provenance_eligibility_state == KSU_PROVENANCE_ELIGIBILITY_NONE) {
        ksu_provenance_record_rejection_locked(NULL,
                                                KSU_PROVENANCE_ELIGIBILITY_WRONG_BOOT_STAGE);
    }
    mutex_unlock(&ksu_provenance_eligibility_lock);
}

void ksu_provenance_get_eligibility_info(struct ksu_provenance_eligibility_info_v1 *info)
{
    u64 capabilities;

    memset(info, 0, sizeof(*info));
    info->size = sizeof(*info);
    info->version = KSU_PROVENANCE_UAPI_VERSION;
    ksu_provenance_provider_lsm_diagnostics(&info->core_hook_state, &info->core_hook_error,
                                             &capabilities);

    mutex_lock(&ksu_provenance_eligibility_lock);
    info->eligibility_state = ksu_provenance_eligibility_state;
    info->eligibility_error = ksu_provenance_eligibility_error;
    info->eligibility_generation = ksu_provenance_eligibility_generation;
    if (ksu_provenance_candidate_task) {
        info->candidate_pid = task_pid_nr(ksu_provenance_candidate_task);
        info->candidate_tgid = task_tgid_nr(ksu_provenance_candidate_task);
    }
    info->roles = ksu_provenance_candidate_image.roles;
    info->verifier_error = ksu_provenance_candidate_image.error;
    info->security_epoch = ksu_provenance_candidate_image.security_epoch;
    memcpy(info->image_sha256, ksu_provenance_candidate_image.image_sha256,
           sizeof(info->image_sha256));
    memcpy(info->build_id, ksu_provenance_candidate_image.build_id, sizeof(info->build_id));
    memcpy(info->signing_key_id, ksu_provenance_candidate_image.signing_key_id,
           sizeof(info->signing_key_id));
    info->uapi_min = ksu_provenance_candidate_image.uapi_min;
    info->uapi_max = ksu_provenance_candidate_image.uapi_max;
    mutex_unlock(&ksu_provenance_eligibility_lock);
}

int ksu_provenance_handle_control(struct ksu_provenance_control_cmd_v1 *command)
{
    struct ksu_provenance_claim_supervisor_v1 request;
    struct ksu_provenance_claim_result_v1 result = {
        .size = sizeof(result),
        .version = KSU_PROVENANCE_UAPI_VERSION,
        .result = KSU_PROVENANCE_CLAIM_CORE_PROVIDER_NOT_READY,
    };

    if (!command || command->size != sizeof(*command) ||
        command->version != KSU_PROVENANCE_UAPI_VERSION || command->flags ||
        !ksu_provenance_all_zero(command->reserved, sizeof(command->reserved)))
        return -EINVAL;
    if (command->operation != KSU_PROVENANCE_CONTROL_CLAIM_SUPERVISOR)
        return -EOPNOTSUPP;
    if (command->request_size != sizeof(request) || command->response_size != sizeof(result) ||
        !command->request || !command->response)
        return -EMSGSIZE;
    if (copy_from_user(&request, u64_to_user_ptr(command->request), sizeof(request)))
        return -EFAULT;
    if (request.size != sizeof(request) || request.version != KSU_PROVENANCE_UAPI_VERSION ||
        request.flags ||
        !ksu_provenance_all_zero(request.boot_claim_nonce, sizeof(request.boot_claim_nonce)) ||
        !ksu_provenance_all_zero(request.reserved, sizeof(request.reserved)))
        return -EINVAL;

    mutex_lock(&ksu_provenance_eligibility_lock);
    result.eligibility_state = ksu_provenance_eligibility_state;
    result.eligibility_generation = ksu_provenance_eligibility_generation;
    mutex_unlock(&ksu_provenance_eligibility_lock);
    if (copy_to_user(u64_to_user_ptr(command->response), &result, sizeof(result)))
        return -EFAULT;
    return -EAGAIN;
}
