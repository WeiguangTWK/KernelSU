#include <linux/build_bug.h>
#include <linux/errno.h>
#include <linux/string.h>

#include "provenance/canonical.h"
#include "provenance/context.h"
#include "provenance/eligibility.h"
#include "provenance/image_verify.h"
#include "provenance/provider_lsm.h"
#include "provenance/provenance.h"
#include "uapi/provenance_golden.h"

static int ksu_provenance_initialization_error;

#ifdef CONFIG_KSU_PROVENANCE
static int ksu_provenance_hex_nibble(char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    return -EINVAL;
}

static int ksu_provenance_decode_hex(const char *source, size_t source_size,
                                     u8 *output, size_t output_size)
{
    size_t index;

    if (source_size != output_size * 2)
        return -EMSGSIZE;
    for (index = 0; index < output_size; index++) {
        int high = ksu_provenance_hex_nibble(source[index * 2]);
        int low = ksu_provenance_hex_nibble(source[index * 2 + 1]);

        if (high < 0 || low < 0)
            return -EINVAL;
        output[index] = (high << 4) | low;
    }
    return 0;
}

static int ksu_provenance_canonical_selftest(void)
{
    static const char manifest_hex[] = KSU_PROVENANCE_GOLDEN_MANIFEST_HEX;
    static const char manifest_digest_hex[] = KSU_PROVENANCE_GOLDEN_MANIFEST_DIGEST_HEX;
    static const char previous_hex[] = KSU_PROVENANCE_GOLDEN_EVENT_PREVIOUS_HEX;
    static const char frame_hex[] = KSU_PROVENANCE_GOLDEN_EVENT_FRAME_HEX;
    static const char event_digest_hex[] = KSU_PROVENANCE_GOLDEN_EVENT_DIGEST_HEX;
    u8 manifest[sizeof(struct ksu_provenance_image_manifest_v1)];
    u8 previous[KSU_PROVENANCE_SHA256_SIZE];
    u8 frame[128];
    u8 expected[KSU_PROVENANCE_SHA256_SIZE];
    u8 digest[KSU_PROVENANCE_SHA256_SIZE];
    int error;

    error = ksu_provenance_decode_hex(manifest_hex, sizeof(manifest_hex) - 1,
                                      manifest, sizeof(manifest));
    if (error)
        return error;
    error = ksu_provenance_decode_hex(manifest_digest_hex,
                                      sizeof(manifest_digest_hex) - 1,
                                      expected, sizeof(expected));
    if (error)
        return error;
    error = ksu_provenance_hash_manifest(manifest, sizeof(manifest), digest);
    if (error || memcmp(digest, expected, sizeof(digest)))
        return error ?: -EBADMSG;

    error = ksu_provenance_decode_hex(previous_hex, sizeof(previous_hex) - 1,
                                      previous, sizeof(previous));
    if (error)
        return error;
    error = ksu_provenance_decode_hex(frame_hex, sizeof(frame_hex) - 1,
                                      frame, sizeof(frame));
    if (error)
        return error;
    error = ksu_provenance_decode_hex(event_digest_hex,
                                      sizeof(event_digest_hex) - 1,
                                      expected, sizeof(expected));
    if (error)
        return error;
    error = ksu_provenance_hash_event(previous, frame, sizeof(frame), digest);
    if (error || memcmp(digest, expected, sizeof(digest)))
        return error ?: -EBADMSG;
    return 0;
}
#endif

int ksu_provenance_init(void)
{
    int error = 0;

    BUILD_BUG_ON(sizeof(struct ksu_provenance_event_header_v1) != 128);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_context_descriptor_v1) != 224);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_barrier_result_v1) != 96);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_control_cmd_v1) != 64);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_claim_supervisor_v1) != 64);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_claim_result_v1) != 32);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_create_launch_v1) != 256);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_create_launch_result_v1) != 32);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_activate_v1) != 32);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_activate_result_v1) != 32);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_close_context_v1) != 32);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_supervisor_ready_v1) != 32);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_current_context_v1) != 64);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_context_status_v1) != 128);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_eligibility_info_v1) != 192);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_info_v1) != 192);
    BUILD_BUG_ON(sizeof(struct ksu_provenance_image_manifest_v1) != 192);
    BUILD_BUG_ON(sizeof(KSU_PROVENANCE_GOLDEN_MANIFEST_HEX) != 385);
    BUILD_BUG_ON(sizeof(KSU_PROVENANCE_GOLDEN_MANIFEST_DIGEST_HEX) != 65);
    BUILD_BUG_ON(sizeof(KSU_PROVENANCE_GOLDEN_EVENT_PREVIOUS_HEX) != 65);
    BUILD_BUG_ON(sizeof(KSU_PROVENANCE_GOLDEN_EVENT_FRAME_HEX) != 257);
    BUILD_BUG_ON(sizeof(KSU_PROVENANCE_GOLDEN_EVENT_DIGEST_HEX) != 65);

#ifdef CONFIG_KSU_PROVENANCE
    error = ksu_provenance_canonical_selftest();
#endif
    if (!error)
        error = ksu_provenance_image_verifier_init();
#ifdef CONFIG_KSU_PROVENANCE
    if (!error)
        error = ksu_provenance_eligibility_init();
    if (!error)
        error = ksu_provenance_context_init();
    if (!error)
        error = ksu_provenance_provider_lsm_init();
#endif
    ksu_provenance_initialization_error = error;
    return error;
}

void ksu_provenance_exit(void)
{
#ifdef CONFIG_KSU_PROVENANCE
    ksu_provenance_provider_lsm_exit();
    ksu_provenance_context_exit();
    ksu_provenance_eligibility_exit();
#endif
    ksu_provenance_image_verifier_exit();
}

void ksu_provenance_get_info(struct ksu_provenance_info_v1 *info)
{
    u64 verifier_capabilities = 0;
    u64 core_capabilities = 0;
    u32 core_state;
    u32 core_error;

    memset(info, 0, sizeof(*info));
    info->size = sizeof(*info);
    info->version = KSU_PROVENANCE_UAPI_VERSION;
    info->trust_tier = KSU_PROVENANCE_TIER_P0;
    info->event_schema_version = KSU_PROVENANCE_EVENT_SCHEMA_VERSION;
    info->manifest_format_version = KSU_PROVENANCE_MANIFEST_FORMAT_VERSION;
    info->uapi_min = KSU_PROVENANCE_UAPI_VERSION;
    info->uapi_max = KSU_PROVENANCE_UAPI_VERSION;
    info->diagnostic_capabilities = KSU_PROVENANCE_CAP_UAPI_V1;

#ifdef CONFIG_KSU_PROVENANCE
    info->provider_state = ksu_provenance_initialization_error ?
        KSU_PROVENANCE_PROVIDER_FAILED : KSU_PROVENANCE_PROVIDER_DIAGNOSTIC;
    info->diagnostic_capabilities |= KSU_PROVENANCE_CAP_CANONICAL_HASH_V1;
#else
    info->provider_state = KSU_PROVENANCE_PROVIDER_DISABLED;
#endif

    ksu_provenance_image_verifier_diagnostics(
        &info->verifier_state, &info->verifier_error,
        &info->minimum_security_epoch, info->signing_key_id,
        &verifier_capabilities);
    info->diagnostic_capabilities |= verifier_capabilities;
#ifdef CONFIG_KSU_PROVENANCE
    ksu_provenance_provider_lsm_diagnostics(&core_state, &core_error,
                                             &core_capabilities);
    info->diagnostic_capabilities |= core_capabilities;
#endif

#ifdef CONFIG_KSU_PROVENANCE
    info->operational_capabilities =
        ksu_provenance_operational_capabilities();
    ksu_provenance_get_boot_epoch(info->boot_epoch);
    if (info->operational_capabilities) {
        info->provider_state = KSU_PROVENANCE_PROVIDER_READY;
        if (ksu_provenance_supervisor_state() ==
                KSU_PROVENANCE_SUPERVISOR_READY &&
            ksu_provenance_last_gap_reason() == KSU_PROVENANCE_GAP_NONE)
            info->trust_tier = KSU_PROVENANCE_TIER_P1;
    }
#endif
    info->intent_operation_classes = 0;
    info->result_operation_classes = 0;
}

void ksu_provenance_get_context_status(
    struct ksu_provenance_context_status_v1 *status)
{
#ifdef CONFIG_KSU_PROVENANCE
    ksu_provenance_fill_context_status(status);
#else
    memset(status, 0, sizeof(*status));
    status->size = sizeof(*status);
    status->version = KSU_PROVENANCE_UAPI_VERSION;
    status->supervisor_state = KSU_PROVENANCE_SUPERVISOR_NONE;
    status->last_gap_reason = KSU_PROVENANCE_GAP_PROVIDER_LOSS;
#endif
}

int ksu_provenance_get_current_context(
    struct ksu_provenance_current_context_v1 *current_context)
{
#ifdef CONFIG_KSU_PROVENANCE
    return ksu_provenance_fill_current_context(current_context);
#else
    memset(current_context, 0, sizeof(*current_context));
    current_context->size = sizeof(*current_context);
    current_context->version = KSU_PROVENANCE_UAPI_VERSION;
    return -EOPNOTSUPP;
#endif
}
