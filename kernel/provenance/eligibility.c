#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "ksu.h"
#include "provenance/context.h"
#include "provenance/eligibility.h"
#include "provenance/image_verify.h"
#include "provenance/provider_lsm.h"
#include "runtime/ksud.h"
#include "uapi/provenance.h"
#include "util.h"

#define KSU_PROVENANCE_SIDECAR_PATH KSUD_PATH ".provenance"
#define KSU_PROVENANCE_MAX_ELIGIBLE_TASKS 8

struct ksu_provenance_candidate {
    struct pid *pid;
    struct pid *tgid;
    struct ksu_provenance_verified_image image;
    u64 generation;
    u32 state;
};

static DEFINE_MUTEX(ksu_provenance_eligibility_lock);
static struct ksu_provenance_candidate
    ksu_provenance_candidates[KSU_PROVENANCE_MAX_ELIGIBLE_TASKS];
static int ksu_provenance_latest_candidate = -1;
static struct ksu_provenance_verified_image
    ksu_provenance_last_rejected_image;
static u32 ksu_provenance_eligibility_state = KSU_PROVENANCE_ELIGIBILITY_NONE;
static u32 ksu_provenance_eligibility_error = KSU_PROVENANCE_ELIGIBILITY_OK;
static u64 ksu_provenance_eligibility_generation;
static bool ksu_provenance_post_fs_data_seen;
static u8 ksu_provenance_boot_claim_nonce[16];
static bool ksu_provenance_boot_claim_nonce_consumed;

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

static struct ksu_provenance_candidate *
ksu_provenance_find_candidate_locked(struct task_struct *task)
{
    unsigned int index;

    for (index = 0; index < KSU_PROVENANCE_MAX_ELIGIBLE_TASKS; index++) {
        struct ksu_provenance_candidate *candidate =
            &ksu_provenance_candidates[index];

        if (candidate->pid == task_pid(task) &&
            candidate->tgid == task_tgid(task))
            return candidate;
    }
    return NULL;
}

static bool ksu_provenance_has_candidate_locked(void)
{
    unsigned int index;

    for (index = 0; index < KSU_PROVENANCE_MAX_ELIGIBLE_TASKS; index++) {
        if (ksu_provenance_candidates[index].pid)
            return true;
    }
    return false;
}

static void ksu_provenance_clear_candidate_locked(
    struct ksu_provenance_candidate *candidate)
{
    if (!candidate)
        return;
    if (candidate->pid)
        put_pid(candidate->pid);
    if (candidate->tgid)
        put_pid(candidate->tgid);
    memset(candidate, 0, sizeof(*candidate));
}

static void ksu_provenance_clear_candidates_locked(void)
{
    unsigned int index;

    for (index = 0; index < KSU_PROVENANCE_MAX_ELIGIBLE_TASKS; index++)
        ksu_provenance_clear_candidate_locked(
            &ksu_provenance_candidates[index]);
    ksu_provenance_latest_candidate = -1;
}

static struct ksu_provenance_candidate *
ksu_provenance_latest_candidate_locked(void)
{
    if (ksu_provenance_latest_candidate < 0)
        return NULL;
    return &ksu_provenance_candidates[ksu_provenance_latest_candidate];
}

static void ksu_provenance_record_rejection_locked(
    const struct ksu_provenance_verified_image *image, u32 error)
{
    if (ksu_provenance_has_candidate_locked())
        return;
    if (ksu_provenance_post_fs_data_seen &&
        ksu_provenance_eligibility_state == KSU_PROVENANCE_ELIGIBILITY_REJECTED)
        return;

    ksu_provenance_clear_candidates_locked();
    memset(&ksu_provenance_last_rejected_image, 0,
           sizeof(ksu_provenance_last_rejected_image));
    if (image)
        ksu_provenance_last_rejected_image = *image;
    ksu_provenance_eligibility_state = KSU_PROVENANCE_ELIGIBILITY_REJECTED;
    ksu_provenance_eligibility_error = error;
}

static void ksu_provenance_record_candidate_locked(
    struct task_struct *task, const struct ksu_provenance_verified_image *image)
{
    struct ksu_provenance_candidate *candidate = NULL;
    unsigned int index;

    if (ksu_provenance_has_candidate_locked() &&
        !ksu_provenance_post_fs_data_seen)
        return;

    candidate = ksu_provenance_find_candidate_locked(task);
    if (!candidate) {
        for (index = 0; index < KSU_PROVENANCE_MAX_ELIGIBLE_TASKS;
             index++) {
            if (!ksu_provenance_candidates[index].pid) {
                candidate = &ksu_provenance_candidates[index];
                break;
            }
        }
    }
    if (!candidate) {
        ksu_provenance_clear_candidates_locked();
        ksu_provenance_eligibility_state =
            KSU_PROVENANCE_ELIGIBILITY_REJECTED;
        ksu_provenance_eligibility_error =
            KSU_PROVENANCE_ELIGIBILITY_INTERNAL;
        return;
    }

    ksu_provenance_clear_candidate_locked(candidate);
    candidate->pid = get_pid(task_pid(task));
    candidate->tgid = get_pid(task_tgid(task));
    candidate->image = *image;
    memset(&ksu_provenance_last_rejected_image, 0,
           sizeof(ksu_provenance_last_rejected_image));
    ksu_provenance_eligibility_generation++;
    if (!ksu_provenance_eligibility_generation)
        ksu_provenance_eligibility_generation = 1;
    candidate->generation = ksu_provenance_eligibility_generation;
    candidate->state = ksu_provenance_post_fs_data_seen ?
        KSU_PROVENANCE_ELIGIBILITY_ELIGIBLE :
        KSU_PROVENANCE_ELIGIBILITY_PENDING_STAGE;
    ksu_provenance_latest_candidate =
        (int)(candidate - ksu_provenance_candidates);
    ksu_provenance_eligibility_state = ksu_provenance_post_fs_data_seen ?
        KSU_PROVENANCE_ELIGIBILITY_ELIGIBLE :
        KSU_PROVENANCE_ELIGIBILITY_PENDING_STAGE;
    ksu_provenance_eligibility_error = KSU_PROVENANCE_ELIGIBILITY_OK;
}

int ksu_provenance_eligibility_init(void)
{
    mutex_lock(&ksu_provenance_eligibility_lock);
    ksu_provenance_clear_candidates_locked();
    memset(&ksu_provenance_last_rejected_image, 0,
           sizeof(ksu_provenance_last_rejected_image));
    ksu_provenance_eligibility_state = KSU_PROVENANCE_ELIGIBILITY_NONE;
    ksu_provenance_eligibility_error = KSU_PROVENANCE_ELIGIBILITY_OK;
    ksu_provenance_eligibility_generation = 0;
    ksu_provenance_post_fs_data_seen = false;
    get_random_bytes(ksu_provenance_boot_claim_nonce,
                     sizeof(ksu_provenance_boot_claim_nonce));
    if (ksu_provenance_all_zero(ksu_provenance_boot_claim_nonce,
                                sizeof(ksu_provenance_boot_claim_nonce)))
        ksu_provenance_boot_claim_nonce[0] = 1;
    ksu_provenance_boot_claim_nonce_consumed = false;
    mutex_unlock(&ksu_provenance_eligibility_lock);
    return 0;
}

void ksu_provenance_eligibility_exit(void)
{
    mutex_lock(&ksu_provenance_eligibility_lock);
    ksu_provenance_clear_candidates_locked();
    memset(&ksu_provenance_last_rejected_image, 0,
           sizeof(ksu_provenance_last_rejected_image));
    ksu_provenance_eligibility_state = KSU_PROVENANCE_ELIGIBILITY_NONE;
    ksu_provenance_eligibility_error = KSU_PROVENANCE_ELIGIBILITY_OK;
    ksu_provenance_eligibility_generation = 0;
    ksu_provenance_post_fs_data_seen = false;
    memzero_explicit(ksu_provenance_boot_claim_nonce,
                     sizeof(ksu_provenance_boot_claim_nonce));
    ksu_provenance_boot_claim_nonce_consumed = true;
    mutex_unlock(&ksu_provenance_eligibility_lock);
}

void ksu_provenance_consider_exec(struct linux_binprm *bprm)
{
    struct ksu_provenance_verified_image verified = { 0 };
    int error;

    if (!bprm || !ksu_provenance_is_ksud_exec_file(bprm->file))
        return;
    if (ksu_provenance_supervisor_state() ==
            KSU_PROVENANCE_SUPERVISOR_CLAIMED ||
        ksu_provenance_supervisor_state() ==
            KSU_PROVENANCE_SUPERVISOR_READY)
        return;

    if (ksu_late_loaded) {
        mutex_lock(&ksu_provenance_eligibility_lock);
        ksu_provenance_record_rejection_locked(NULL, KSU_PROVENANCE_ELIGIBILITY_LATE_LOAD);
        mutex_unlock(&ksu_provenance_eligibility_lock);
        return;
    }

    mutex_lock(&ksu_provenance_eligibility_lock);
    if (ksu_provenance_has_candidate_locked() &&
        !ksu_provenance_post_fs_data_seen) {
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
    struct ksu_provenance_candidate *candidate;

    mutex_lock(&ksu_provenance_eligibility_lock);
    ksu_provenance_post_fs_data_seen = true;
    candidate = ksu_provenance_find_candidate_locked(task);
    if (candidate && candidate->state ==
                         KSU_PROVENANCE_ELIGIBILITY_PENDING_STAGE) {
        candidate->state = KSU_PROVENANCE_ELIGIBILITY_ELIGIBLE;
        ksu_provenance_eligibility_state = KSU_PROVENANCE_ELIGIBILITY_ELIGIBLE;
        ksu_provenance_eligibility_error = KSU_PROVENANCE_ELIGIBILITY_OK;
    } else if (ksu_provenance_eligibility_state ==
               KSU_PROVENANCE_ELIGIBILITY_PENDING_STAGE) {
        ksu_provenance_clear_candidates_locked();
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
    struct ksu_provenance_candidate *candidate;
    u64 capabilities;

    memset(info, 0, sizeof(*info));
    info->size = sizeof(*info);
    info->version = KSU_PROVENANCE_UAPI_VERSION;
    ksu_provenance_provider_lsm_diagnostics(&info->core_hook_state, &info->core_hook_error,
                                             &capabilities);

    mutex_lock(&ksu_provenance_eligibility_lock);
    candidate = ksu_provenance_find_candidate_locked(current);
    if (!candidate)
        candidate = ksu_provenance_latest_candidate_locked();
    info->eligibility_state = ksu_provenance_eligibility_state;
    info->eligibility_error = ksu_provenance_eligibility_error;
    info->eligibility_generation = candidate ?
        candidate->generation : ksu_provenance_eligibility_generation;
    if (candidate) {
        info->eligibility_state = candidate->state;
        info->candidate_pid = pid_nr(candidate->pid);
        info->candidate_tgid = pid_nr(candidate->tgid);
        info->roles = candidate->image.roles;
        info->verifier_error = candidate->image.error;
        info->security_epoch = candidate->image.security_epoch;
        memcpy(info->image_sha256, candidate->image.image_sha256,
               sizeof(info->image_sha256));
        memcpy(info->build_id, candidate->image.build_id,
               sizeof(info->build_id));
        memcpy(info->signing_key_id, candidate->image.signing_key_id,
               sizeof(info->signing_key_id));
        info->uapi_min = candidate->image.uapi_min;
        info->uapi_max = candidate->image.uapi_max;
    } else {
        info->roles = ksu_provenance_last_rejected_image.roles;
        info->verifier_error = ksu_provenance_last_rejected_image.error;
        info->security_epoch =
            ksu_provenance_last_rejected_image.security_epoch;
        memcpy(info->image_sha256,
               ksu_provenance_last_rejected_image.image_sha256,
               sizeof(info->image_sha256));
        memcpy(info->build_id, ksu_provenance_last_rejected_image.build_id,
               sizeof(info->build_id));
        memcpy(info->signing_key_id,
               ksu_provenance_last_rejected_image.signing_key_id,
               sizeof(info->signing_key_id));
        info->uapi_min = ksu_provenance_last_rejected_image.uapi_min;
        info->uapi_max = ksu_provenance_last_rejected_image.uapi_max;
    }
    mutex_unlock(&ksu_provenance_eligibility_lock);
}

int ksu_provenance_handle_control(struct ksu_provenance_control_cmd_v1 *command)
{
    struct ksu_provenance_candidate *candidate;
    struct ksu_provenance_claim_supervisor_v1 request;
    struct ksu_provenance_verified_image image;
    struct ksu_provenance_claim_result_v1 result = {
        .size = sizeof(result),
        .version = KSU_PROVENANCE_UAPI_VERSION,
        .result = KSU_PROVENANCE_CLAIM_CORE_PROVIDER_NOT_READY,
        .endpoint_fd = -1,
        .supervisor_state = KSU_PROVENANCE_SUPERVISOR_NONE,
    };
    bool matching_nonce_consumed = false;
    int error = 0;

    if (!command || command->size != sizeof(*command) ||
        command->version != KSU_PROVENANCE_UAPI_VERSION || command->flags ||
        !ksu_provenance_all_zero(command->reserved, sizeof(command->reserved)))
        return -EINVAL;
    if (command->operation != KSU_PROVENANCE_CONTROL_CLAIM_SUPERVISOR)
        return ksu_provenance_context_handle_control(command);
    if (command->request_size != sizeof(request) || command->response_size != sizeof(result) ||
        !command->request || !command->response)
        return -EMSGSIZE;
    if (copy_from_user(&request, u64_to_user_ptr(command->request), sizeof(request)))
        return -EFAULT;
    if (request.size != sizeof(request) || request.version != KSU_PROVENANCE_UAPI_VERSION ||
        request.flags ||
        !ksu_provenance_all_zero(request.reserved, sizeof(request.reserved)))
        return -EINVAL;

    mutex_lock(&ksu_provenance_eligibility_lock);
    candidate = ksu_provenance_find_candidate_locked(current);
    result.eligibility_state = ksu_provenance_eligibility_state;
    result.eligibility_generation = candidate ?
        candidate->generation : ksu_provenance_eligibility_generation;
    result.supervisor_state = ksu_provenance_supervisor_state();
    if (memcmp(request.boot_claim_nonce,
                      ksu_provenance_boot_claim_nonce,
                      sizeof(request.boot_claim_nonce))) {
        result.result = KSU_PROVENANCE_CLAIM_WRONG_NONCE;
        error = -EKEYREJECTED;
    } else if (ksu_provenance_boot_claim_nonce_consumed) {
        result.result = KSU_PROVENANCE_CLAIM_NONCE_CONSUMED;
        error = -EALREADY;
    } else {
        ksu_provenance_boot_claim_nonce_consumed = true;
        matching_nonce_consumed = true;
        if (ksu_late_loaded) {
            result.result = KSU_PROVENANCE_CLAIM_LATE_LOAD;
            error = -EOPNOTSUPP;
        } else if (!candidate || candidate->state !=
                                      KSU_PROVENANCE_ELIGIBILITY_ELIGIBLE) {
            result.result = KSU_PROVENANCE_CLAIM_NO_ELIGIBLE_TASK;
            error = -EPERM;
        } else if (request.eligibility_generation !=
                   candidate->generation) {
            result.result = KSU_PROVENANCE_CLAIM_WRONG_GENERATION;
            error = -ESTALE;
        } else {
            image = candidate->image;
            error = ksu_provenance_claim_supervisor(
                &image, candidate->generation, &result);
        }
        if (error)
            ksu_provenance_clear_candidates_locked();
    }
    mutex_unlock(&ksu_provenance_eligibility_lock);
    if (matching_nonce_consumed && error)
        ksu_provenance_fail_supervisor_claim();
    if (copy_to_user(u64_to_user_ptr(command->response), &result, sizeof(result))) {
        if (result.endpoint_fd >= 0)
            ksu_close_fd(result.endpoint_fd);
        return -EFAULT;
    }
    return error;
}

bool ksu_provenance_get_boot_claim_nonce_hex(char output[33])
{
    static const char hex[] = "0123456789abcdef";
    size_t index;

    mutex_lock(&ksu_provenance_eligibility_lock);
    if (ksu_provenance_all_zero(ksu_provenance_boot_claim_nonce,
                                sizeof(ksu_provenance_boot_claim_nonce))) {
        mutex_unlock(&ksu_provenance_eligibility_lock);
        return false;
    }
    for (index = 0; index < sizeof(ksu_provenance_boot_claim_nonce); index++) {
        output[index * 2] = hex[ksu_provenance_boot_claim_nonce[index] >> 4];
        output[index * 2 + 1] =
            hex[ksu_provenance_boot_claim_nonce[index] & 0x0f];
    }
    output[32] = '\0';
    mutex_unlock(&ksu_provenance_eligibility_lock);
    return true;
}
