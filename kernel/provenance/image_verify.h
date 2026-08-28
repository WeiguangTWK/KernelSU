#ifndef __KSU_PROVENANCE_IMAGE_VERIFY_H
#define __KSU_PROVENANCE_IMAGE_VERIFY_H

#include <linux/fs.h>
#include <linux/string.h>
#include <linux/types.h>

#include "uapi/provenance.h"

struct ksu_provenance_verified_image {
    u32 roles;
    u32 uapi_min;
    u32 uapi_max;
    u64 security_epoch;
    u64 image_size;
    u8 image_sha256[32];
    u8 build_id[32];
    u8 signing_key_id[32];
    u32 error;
};

#ifdef CONFIG_KSU_PROVENANCE
int ksu_provenance_image_verifier_init(void);
void ksu_provenance_image_verifier_exit(void);
/*
 * The caller owns image and must prevent writes for the complete verification
 * and later exec handoff. Phase 1 intentionally has no exec caller.
 */
int ksu_provenance_verify_image(struct file *image, const char *sidecar_path,
                                u32 required_role,
                                struct ksu_provenance_verified_image *verified);
void ksu_provenance_image_verifier_diagnostics(u32 *state, u32 *error,
                                                u64 *minimum_epoch,
                                                u8 key_id[32],
                                                u64 *capabilities);
#else
static inline int ksu_provenance_image_verifier_init(void)
{
    return 0;
}

static inline void ksu_provenance_image_verifier_exit(void)
{
}

static inline void ksu_provenance_image_verifier_diagnostics(u32 *state, u32 *error,
                                                              u64 *minimum_epoch,
                                                              u8 key_id[32],
                                                              u64 *capabilities)
{
    *state = KSU_PROVENANCE_VERIFIER_DISABLED;
    *error = KSU_PROVENANCE_VERIFY_DISABLED;
    *minimum_epoch = 0;
    memset(key_id, 0, 32);
    *capabilities = 0;
}
#endif

#endif /* __KSU_PROVENANCE_IMAGE_VERIFY_H */
