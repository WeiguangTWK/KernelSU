#ifndef __KSU_UAPI_PROVENANCE_H
#define __KSU_UAPI_PROVENANCE_H

#include <linux/ioctl.h>
#include <linux/types.h>

/*
 * Audit provenance UAPI version 1.
 *
 * IOCTL structures use the native little-endian representation used by the
 * supported Android arm64 and x86_64 targets. Canonical manifest and event
 * bytes are explicitly little-endian and must not be produced by dumping a
 * native structure on an unsupported big-endian host.
 */
static const __u16 KSU_PROVENANCE_UAPI_VERSION = 1;
static const __u16 KSU_PROVENANCE_EVENT_SCHEMA_VERSION = 1;
static const __u16 KSU_PROVENANCE_MANIFEST_FORMAT_VERSION = 1;

static const __u32 KSU_PROVENANCE_EVENT_MAGIC = 0x5650534b; /* "KSPV" */
static const __u32 KSU_PROVENANCE_MANIFEST_SIZE_V1 = 192;
static const __u32 KSU_PROVENANCE_MANIFEST_MAX_SIZE = 512;
static const __u32 KSU_PROVENANCE_RSA3072_SIGNATURE_SIZE = 384;
static const __u32 KSU_PROVENANCE_SIDECAR_SIZE_V1 = 576;
static const __u64 KSU_PROVENANCE_MAX_IMAGE_SIZE = 64ULL * 1024ULL * 1024ULL;

static const __u32 KSU_PROVENANCE_ROLE_SUPERVISOR = (1U << 0);
static const __u32 KSU_PROVENANCE_ROLE_INIT_PROXY = (1U << 1);
static const __u32 KSU_PROVENANCE_ROLE_MASK_V1 = (1U << 0) | (1U << 1);

/* Diagnostic and operational capability bits share one stable namespace. */
static const __u64 KSU_PROVENANCE_CAP_UAPI_V1 = (1ULL << 0);
static const __u64 KSU_PROVENANCE_CAP_CANONICAL_HASH_V1 = (1ULL << 1);
static const __u64 KSU_PROVENANCE_CAP_IMAGE_VERIFIER_V1 = (1ULL << 2);
static const __u64 KSU_PROVENANCE_CAP_SIGNING_KEY_V1 = (1ULL << 3);
static const __u64 KSU_PROVENANCE_CAP_CORE_HOOK_DIAGNOSTIC_V1 = (1ULL << 4);
static const __u64 KSU_PROVENANCE_CAP_SIGNED_EXEC_ELIGIBILITY_V1 = (1ULL << 5);
static const __u64 KSU_PROVENANCE_CAP_SUPERVISOR_CLAIM = (1ULL << 8);
static const __u64 KSU_PROVENANCE_CAP_TASK_CONTEXT = (1ULL << 9);
static const __u64 KSU_PROVENANCE_CAP_CREDENTIAL_CONTEXT = (1ULL << 10);
static const __u64 KSU_PROVENANCE_CAP_LAUNCH_ENDPOINT = (1ULL << 11);
static const __u64 KSU_PROVENANCE_CAP_CONTROL_ISOLATION = (1ULL << 12);
static const __u64 KSU_PROVENANCE_CAP_SCHED_RECONCILIATION = (1ULL << 13);
static const __u64 KSU_PROVENANCE_CAP_IO_URING_CREDENTIAL = (1ULL << 14);

static const __u32 KSU_PROVENANCE_READY_IO_URING_TESTED = (1U << 0);
static const __u64 KSU_PROVENANCE_CAP_INTENT_FILE = (1ULL << 16);
static const __u64 KSU_PROVENANCE_CAP_INTENT_INODE = (1ULL << 17);
static const __u64 KSU_PROVENANCE_CAP_INTENT_MOUNT = (1ULL << 18);
static const __u64 KSU_PROVENANCE_CAP_RESULT_VFS = (1ULL << 24);
static const __u64 KSU_PROVENANCE_CAP_EVENT_STREAM = (1ULL << 32);
static const __u64 KSU_PROVENANCE_CAP_ROLLING_DIGEST = (1ULL << 33);
static const __u64 KSU_PROVENANCE_CAP_BARRIER = (1ULL << 34);
static const __u64 KSU_PROVENANCE_CAP_INIT_PROXY = (1ULL << 40);
static const __u64 KSU_PROVENANCE_CAP_RESPONSE_GUARD = (1ULL << 48);

/* Capability groups reserve eight bits each for compatible growth. */
static const __u64 KSU_PROVENANCE_CAP_GROUP_DIAGNOSTIC = (0xffULL << 0);
static const __u64 KSU_PROVENANCE_CAP_GROUP_CONTEXT = (0xffULL << 8);
static const __u64 KSU_PROVENANCE_CAP_GROUP_INTENT = (0xffULL << 16);
static const __u64 KSU_PROVENANCE_CAP_GROUP_RESULT = (0xffULL << 24);
static const __u64 KSU_PROVENANCE_CAP_GROUP_STREAM = (0xffULL << 32);
static const __u64 KSU_PROVENANCE_CAP_GROUP_INIT = (0xffULL << 40);
static const __u64 KSU_PROVENANCE_CAP_GROUP_RESPONSE = (0xffULL << 48);

static const __u32 KSU_PROVENANCE_EVENT_FLAGS_V1 = 0;
static const __u32 KSU_PROVENANCE_CONTEXT_FLAGS_V1 = 0;
static const __u32 KSU_PROVENANCE_BARRIER_FLAGS_V1 = 0;
static const __u32 KSU_PROVENANCE_CONTROL_FLAGS_V1 = 0;
static const __u32 KSU_PROVENANCE_INFO_FLAGS_V1 = 0;
static const __u32 KSU_PROVENANCE_MANIFEST_FLAGS_V1 = 0;

enum ksu_provenance_provider_state {
    KSU_PROVENANCE_PROVIDER_DISABLED = 0,
    KSU_PROVENANCE_PROVIDER_DIAGNOSTIC = 1,
    KSU_PROVENANCE_PROVIDER_READY = 2,
    KSU_PROVENANCE_PROVIDER_DEGRADED = 3,
    KSU_PROVENANCE_PROVIDER_FAILED = 4,
};

enum ksu_provenance_trust_tier {
    KSU_PROVENANCE_TIER_P0 = 0,
    KSU_PROVENANCE_TIER_P1 = 1,
    KSU_PROVENANCE_TIER_P2 = 2,
    KSU_PROVENANCE_TIER_P3 = 3,
    KSU_PROVENANCE_TIER_P4 = 4,
    KSU_PROVENANCE_TIER_P5 = 5,
};

enum ksu_provenance_verifier_state {
    KSU_PROVENANCE_VERIFIER_DISABLED = 0,
    KSU_PROVENANCE_VERIFIER_NOT_CONFIGURED = 1,
    KSU_PROVENANCE_VERIFIER_READY = 2,
    KSU_PROVENANCE_VERIFIER_FAILED = 3,
};

enum ksu_provenance_verifier_error {
    KSU_PROVENANCE_VERIFY_OK = 0,
    KSU_PROVENANCE_VERIFY_DISABLED = 1,
    KSU_PROVENANCE_VERIFY_NO_KEY = 2,
    KSU_PROVENANCE_VERIFY_CERT_PARSE = 3,
    KSU_PROVENANCE_VERIFY_CERT_KEY = 4,
    KSU_PROVENANCE_VERIFY_CERT_KEY_ID = 5,
    KSU_PROVENANCE_VERIFY_SIDECAR_OPEN = 6,
    KSU_PROVENANCE_VERIFY_SIDECAR_TYPE = 7,
    KSU_PROVENANCE_VERIFY_SIDECAR_SIZE = 8,
    KSU_PROVENANCE_VERIFY_SIDECAR_READ = 9,
    KSU_PROVENANCE_VERIFY_MANIFEST_MAGIC = 10,
    KSU_PROVENANCE_VERIFY_MANIFEST_VERSION = 11,
    KSU_PROVENANCE_VERIFY_MANIFEST_LENGTH = 12,
    KSU_PROVENANCE_VERIFY_MANIFEST_FLAGS = 13,
    KSU_PROVENANCE_VERIFY_MANIFEST_RESERVED = 14,
    KSU_PROVENANCE_VERIFY_ROLE = 15,
    KSU_PROVENANCE_VERIFY_UAPI = 16,
    KSU_PROVENANCE_VERIFY_EPOCH = 17,
    KSU_PROVENANCE_VERIFY_KEY_ID = 18,
    KSU_PROVENANCE_VERIFY_IMAGE_TYPE = 19,
    KSU_PROVENANCE_VERIFY_IMAGE_SIZE = 20,
    KSU_PROVENANCE_VERIFY_IMAGE_READ = 21,
    KSU_PROVENANCE_VERIFY_IMAGE_DIGEST = 22,
    KSU_PROVENANCE_VERIFY_SIGNATURE = 23,
    KSU_PROVENANCE_VERIFY_CRYPTO = 24,
    KSU_PROVENANCE_VERIFY_INTERNAL = 25,
};

enum ksu_provenance_core_hook_state {
    KSU_PROVENANCE_CORE_HOOK_DISABLED = 0,
    KSU_PROVENANCE_CORE_HOOK_INSTALLED = 1,
    KSU_PROVENANCE_CORE_HOOK_FAILED = 2,
    KSU_PROVENANCE_CORE_HOOK_RESTORED = 3,
};

enum ksu_provenance_core_hook_error {
    KSU_PROVENANCE_CORE_HOOK_OK = 0,
    KSU_PROVENANCE_CORE_HOOK_NOT_CONFIGURED = 1,
    KSU_PROVENANCE_CORE_HOOK_VERIFIER_NOT_READY = 2,
    KSU_PROVENANCE_CORE_HOOK_TARGET_ABSENT = 3,
    KSU_PROVENANCE_CORE_HOOK_TARGET_DUPLICATE = 4,
    KSU_PROVENANCE_CORE_HOOK_SLOT_UNEXPECTED = 5,
    KSU_PROVENANCE_CORE_HOOK_SLOT_CHANGED = 6,
    KSU_PROVENANCE_CORE_HOOK_INSTALL = 7,
    KSU_PROVENANCE_CORE_HOOK_ROLLBACK = 8,
    KSU_PROVENANCE_CORE_HOOK_SELFTEST = 9,
};

enum ksu_provenance_eligibility_state {
    KSU_PROVENANCE_ELIGIBILITY_NONE = 0,
    KSU_PROVENANCE_ELIGIBILITY_PENDING_STAGE = 1,
    KSU_PROVENANCE_ELIGIBILITY_ELIGIBLE = 2,
    KSU_PROVENANCE_ELIGIBILITY_REJECTED = 3,
};

enum ksu_provenance_eligibility_error {
    KSU_PROVENANCE_ELIGIBILITY_OK = 0,
    KSU_PROVENANCE_ELIGIBILITY_CORE_PROVIDER_NOT_READY = 1,
    KSU_PROVENANCE_ELIGIBILITY_WRONG_PARENT = 2,
    KSU_PROVENANCE_ELIGIBILITY_WRONG_BOOT_STAGE = 3,
    KSU_PROVENANCE_ELIGIBILITY_IMAGE = 4,
    KSU_PROVENANCE_ELIGIBILITY_ROLE = 5,
    KSU_PROVENANCE_ELIGIBILITY_UAPI = 6,
    KSU_PROVENANCE_ELIGIBILITY_EPOCH = 7,
    KSU_PROVENANCE_ELIGIBILITY_GENERATION = 8,
    KSU_PROVENANCE_ELIGIBILITY_LATE_LOAD = 9,
    KSU_PROVENANCE_ELIGIBILITY_INTERNAL = 10,
};

enum ksu_provenance_claim_result {
    KSU_PROVENANCE_CLAIM_RESULT_OK = 0,
    KSU_PROVENANCE_CLAIM_CORE_PROVIDER_NOT_READY = 1,
    KSU_PROVENANCE_CLAIM_NO_ELIGIBLE_TASK = 2,
    KSU_PROVENANCE_CLAIM_WRONG_GENERATION = 3,
    KSU_PROVENANCE_CLAIM_WRONG_NONCE = 4,
    KSU_PROVENANCE_CLAIM_NONCE_CONSUMED = 5,
    KSU_PROVENANCE_CLAIM_ALREADY_CLAIMED = 6,
    KSU_PROVENANCE_CLAIM_LATE_LOAD = 7,
    KSU_PROVENANCE_CLAIM_INTERNAL = 8,
};

enum ksu_provenance_supervisor_state {
    KSU_PROVENANCE_SUPERVISOR_NONE = 0,
    KSU_PROVENANCE_SUPERVISOR_CLAIMED = 1,
    KSU_PROVENANCE_SUPERVISOR_READY = 2,
    KSU_PROVENANCE_SUPERVISOR_LOST = 3,
    KSU_PROVENANCE_SUPERVISOR_DRAINING = 4,
    KSU_PROVENANCE_SUPERVISOR_FAILED = 5,
};

enum ksu_provenance_context_state {
    KSU_PROVENANCE_CONTEXT_PENDING = 0,
    KSU_PROVENANCE_CONTEXT_ACTIVE = 1,
    KSU_PROVENANCE_CONTEXT_CLOSED = 2,
    KSU_PROVENANCE_CONTEXT_INCOMPLETE = 3,
    KSU_PROVENANCE_CONTEXT_DRAINED = 4,
};

enum ksu_provenance_gap_reason {
    KSU_PROVENANCE_GAP_NONE = 0,
    KSU_PROVENANCE_GAP_LATE_LOAD = 1,
    KSU_PROVENANCE_GAP_PROVIDER_LOSS = 2,
    KSU_PROVENANCE_GAP_QUEUE_OVERFLOW = 3,
    KSU_PROVENANCE_GAP_ALLOCATION_FAILURE = 4,
    KSU_PROVENANCE_GAP_CONTEXT_CONFLICT = 5,
    KSU_PROVENANCE_GAP_SUPERVISOR_LOSS = 6,
    KSU_PROVENANCE_GAP_UNSUPPORTED_OPERATION = 7,
    KSU_PROVENANCE_GAP_DELEGATION = 8,
    KSU_PROVENANCE_GAP_PATH_TRUNCATED = 9,
    KSU_PROVENANCE_GAP_UNCLEAN_SHUTDOWN = 10,
    KSU_PROVENANCE_GAP_UNLOAD_RELOAD = 11,
    KSU_PROVENANCE_GAP_INIT_PROXY_REJECTED = 12,
};

enum ksu_provenance_provider {
    KSU_PROVENANCE_PROVIDER_NONE = 0,
    KSU_PROVENANCE_PROVIDER_BUILTIN = 1,
    KSU_PROVENANCE_PROVIDER_LKM = 2,
    KSU_PROVENANCE_PROVIDER_INIT_PROXY = 3,
};

enum ksu_provenance_result_confidence {
    KSU_PROVENANCE_RESULT_UNKNOWN = 0,
    KSU_PROVENANCE_RESULT_OBSERVED = 1,
    KSU_PROVENANCE_RESULT_INFERRED = 2,
    KSU_PROVENANCE_RESULT_CONFIRMED = 3,
};

enum ksu_provenance_event_type {
    KSU_PROVENANCE_EVENT_CONTEXT_OPENED = 1,
    KSU_PROVENANCE_EVENT_CONTEXT_CLOSED = 2,
    KSU_PROVENANCE_EVENT_MUTATION_INTENT = 3,
    KSU_PROVENANCE_EVENT_MUTATION_RESULT = 4,
    KSU_PROVENANCE_EVENT_COVERAGE_GAP = 5,
    KSU_PROVENANCE_EVENT_BARRIER = 6,
    KSU_PROVENANCE_EVENT_DROP = 7,
    KSU_PROVENANCE_EVENT_INIT_PROXY_REJECTED = 8,
};

enum ksu_provenance_operation_class {
    KSU_PROVENANCE_OP_NONE = 0,
    KSU_PROVENANCE_OP_CONTENT_WRITE = 1,
    KSU_PROVENANCE_OP_TRUNCATE = 2,
    KSU_PROVENANCE_OP_CREATE = 3,
    KSU_PROVENANCE_OP_REMOVE = 4,
    KSU_PROVENANCE_OP_RENAME = 5,
    KSU_PROVENANCE_OP_LINK = 6,
    KSU_PROVENANCE_OP_METADATA = 7,
    KSU_PROVENANCE_OP_XATTR = 8,
    KSU_PROVENANCE_OP_MMAP = 9,
    KSU_PROVENANCE_OP_IOCTL = 10,
    KSU_PROVENANCE_OP_MOUNT = 11,
    KSU_PROVENANCE_OP_DESCRIPTOR_RECEIVE = 12,
};

enum ksu_provenance_stage {
    KSU_PROVENANCE_STAGE_UNKNOWN = 0,
    KSU_PROVENANCE_STAGE_INSTALL = 1,
    KSU_PROVENANCE_STAGE_POST_FS_DATA = 2,
    KSU_PROVENANCE_STAGE_SERVICE = 3,
    KSU_PROVENANCE_STAGE_BOOT_COMPLETED = 4,
    KSU_PROVENANCE_STAGE_ACTION = 5,
    KSU_PROVENANCE_STAGE_INIT_SERVICE = 6,
    KSU_PROVENANCE_STAGE_INIT_EXEC = 7,
};

/* Semantic operations carried by the versioned control envelope. */
enum ksu_provenance_control_operation {
    KSU_PROVENANCE_CONTROL_CLAIM_SUPERVISOR = 1,
    KSU_PROVENANCE_CONTROL_CREATE_LAUNCH = 2,
    KSU_PROVENANCE_CONTROL_ACTIVATE = 3,
    KSU_PROVENANCE_CONTROL_CLOSE_CONTEXT = 4,
    KSU_PROVENANCE_CONTROL_BARRIER = 5,
    KSU_PROVENANCE_CONTROL_ACK_SPOOL = 6,
    KSU_PROVENANCE_CONTROL_GET_EVENT_FD = 7,
    KSU_PROVENANCE_CONTROL_REDEEM_INIT_TICKET = 8,
    KSU_PROVENANCE_CONTROL_GET_INIT_REQUEST = 9,
    KSU_PROVENANCE_CONTROL_RESOLVE_INIT_REQUEST = 10,
    KSU_PROVENANCE_CONTROL_BEGIN_RESPONSE_GUARD = 11,
    KSU_PROVENANCE_CONTROL_QUERY_RESPONSE_GUARD = 12,
    KSU_PROVENANCE_CONTROL_END_RESPONSE_GUARD = 13,
    KSU_PROVENANCE_CONTROL_QUERY_CONTEXT = 14,
    KSU_PROVENANCE_CONTROL_SUPERVISOR_READY = 15,
};

/* Exactly 128 canonical bytes before the variable payload. */
struct ksu_provenance_event_header_v1 {
    __u32 magic;
    __u16 version;
    __u16 header_size;
    __u32 frame_size;
    __u16 event_type;
    __u16 flags;
    __aligned_u64 sequence;
    __aligned_u64 monotonic_ns;
    __aligned_u64 supervisor_generation;
    __aligned_u64 context_cookie;
    __aligned_u64 correlation_id;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 euid;
    __u16 operation_class;
    __u16 provider;
    __u16 result_confidence;
    __u16 gap_reason;
    __u32 payload_size;
    __u32 reserved0;
    __u8 boot_epoch[16];
    __u8 reserved1[24];
};

/* Exactly 224 bytes. All identifiers are canonical SHA-256 values. */
struct ksu_provenance_context_descriptor_v1 {
    __u16 size;
    __u16 version;
    __u32 flags;
    __u32 stage;
    __u32 reserved0;
    __u8 actor_id[32];
    __u8 subject_id[32];
    __u8 controller_id[32];
    __u8 script_sha256[32];
    __u8 operation_id[32];
    __u8 reserved1[48];
};

/* Exactly 96 bytes. */
struct ksu_provenance_barrier_result_v1 {
    __u16 size;
    __u16 version;
    __u32 flags;
    __aligned_u64 sequence;
    __aligned_u64 first_gap_sequence;
    __u8 rolling_digest[32];
    __u8 boot_epoch[16];
    __u8 reserved[24];
};

/* Exactly 64 bytes. */
struct ksu_provenance_control_cmd_v1 {
    __u16 size;
    __u16 version;
    __u16 operation;
    __u16 flags;
    __u32 request_size;
    __u32 response_size;
    __aligned_u64 request;
    __aligned_u64 response;
    __aligned_u64 reserved[4];
};

/* Exactly 64 bytes. Phase 3 consumes the matching boot nonce once. */
struct ksu_provenance_claim_supervisor_v1 {
    __u16 size;
    __u16 version;
    __u32 flags;
    __aligned_u64 eligibility_generation;
    __u8 boot_claim_nonce[16];
    __u8 reserved[32];
};

/* Exactly 32 bytes. endpoint_fd is an owned CLOEXEC supervisor endpoint. */
struct ksu_provenance_claim_result_v1 {
    __u16 size;
    __u16 version;
    __u32 flags;
    __u32 result;
    __u32 eligibility_state;
    __aligned_u64 eligibility_generation;
    __s32 endpoint_fd;
    __u32 supervisor_state;
};

/* Exactly 256 bytes. */
struct ksu_provenance_create_launch_v1 {
    __u16 size;
    __u16 version;
    __u32 flags;
    struct ksu_provenance_context_descriptor_v1 descriptor;
    __u32 timeout_ms;
    __u32 reserved0;
    __u8 reserved[16];
};

/* Exactly 32 bytes. */
struct ksu_provenance_create_launch_result_v1 {
    __u16 size;
    __u16 version;
    __u32 flags;
    __s32 endpoint_fd;
    __u32 context_state;
    __aligned_u64 supervisor_generation;
    __aligned_u64 context_cookie;
};

/* Exactly 32 bytes. Sent to the one-use launch endpoint. */
struct ksu_provenance_activate_v1 {
    __u16 size;
    __u16 version;
    __u32 flags;
    __aligned_u64 supervisor_generation;
    __aligned_u64 context_cookie;
    __u8 reserved[8];
};

/* Exactly 32 bytes. */
struct ksu_provenance_activate_result_v1 {
    __u16 size;
    __u16 version;
    __u32 flags;
    __u32 context_state;
    __u32 gap_reason;
    __aligned_u64 supervisor_generation;
    __aligned_u64 context_cookie;
};

/* Exactly 32 bytes. */
struct ksu_provenance_close_context_v1 {
    __u16 size;
    __u16 version;
    __u32 flags;
    __aligned_u64 supervisor_generation;
    __aligned_u64 context_cookie;
    __u8 reserved[8];
};

/* Exactly 32 bytes. */
struct ksu_provenance_supervisor_ready_v1 {
    __u16 size;
    __u16 version;
    __u32 flags;
    __aligned_u64 supervisor_generation;
    __u8 reserved[16];
};

/* Exactly 64 bytes. Read-only identity of the calling task/credential. */
struct ksu_provenance_current_context_v1 {
    __u16 size;
    __u16 version;
    __u32 flags;
    __u32 context_state;
    __u32 gap_reason;
    __aligned_u64 supervisor_generation;
    __aligned_u64 context_cookie;
    __u8 boot_epoch[16];
    __u8 reserved[16];
};

/* Exactly 128 bytes. Read-only Phase 3 state and bounded-map diagnostics. */
struct ksu_provenance_context_status_v1 {
    __u16 size;
    __u16 version;
    __u32 flags;
    __u32 supervisor_state;
    __u32 last_gap_reason;
    __aligned_u64 supervisor_generation;
    __u32 active_contexts;
    __u32 task_bindings;
    __u32 credential_bindings;
    __u32 pending_launches;
    __u32 max_contexts;
    __u32 max_task_bindings;
    __u32 max_credential_bindings;
    __u32 max_pending_launches;
    __aligned_u64 reconciliation_failures;
    __aligned_u64 allocation_failures;
    __u8 boot_epoch[16];
    __u8 reserved[40];
};

/*
 * Exactly 192 bytes of read-only Phase 2 hook and exec diagnostics.
 * eligibility_generation advances for each authenticated candidate record.
 * A caller sees its own record when several init children race at the stage.
 */
struct ksu_provenance_eligibility_info_v1 {
    __u16 size;
    __u16 version;
    __u32 flags;
    __u32 core_hook_state;
    __u32 core_hook_error;
    __u32 eligibility_state;
    __u32 eligibility_error;
    __aligned_u64 eligibility_generation;
    __u32 candidate_pid;
    __u32 candidate_tgid;
    __u32 roles;
    __u32 verifier_error;
    __aligned_u64 security_epoch;
    __u8 image_sha256[32];
    __u8 build_id[32];
    __u8 signing_key_id[32];
    __u32 uapi_min;
    __u32 uapi_max;
    __u8 reserved[32];
};

/* Exactly 192 bytes. */
struct ksu_provenance_info_v1 {
    __u16 size;
    __u16 version;
    __u32 flags;
    __u32 provider_state;
    __u32 trust_tier;
    __aligned_u64 diagnostic_capabilities;
    __aligned_u64 operational_capabilities;
    __aligned_u64 intent_operation_classes;
    __aligned_u64 result_operation_classes;
    __aligned_u64 current_sequence;
    __u8 current_digest[32];
    __u8 boot_epoch[16];
    __u32 event_schema_version;
    __u32 manifest_format_version;
    __u32 uapi_min;
    __u32 uapi_max;
    __u32 verifier_state;
    __u32 verifier_error;
    __aligned_u64 minimum_security_epoch;
    __u8 signing_key_id[32];
    __u8 reserved[24];
};

/* Exactly 192 canonical little-endian bytes, followed by a 384-byte signature. */
struct ksu_provenance_image_manifest_v1 {
    __u8 magic[8];
    __u16 format_version;
    __u16 manifest_size;
    __u32 flags;
    __u32 roles;
    __u32 reserved0;
    __aligned_u64 image_size;
    __u8 image_sha256[32];
    __u8 build_id[32];
    __u32 uapi_min;
    __u32 uapi_max;
    __aligned_u64 security_epoch;
    __u8 signing_key_id[32];
    __u8 reserved1[48];
};

static const __u32 KSU_IOCTL_PROVENANCE_GET_INFO =
    _IOR('K', 32, struct ksu_provenance_info_v1);
static const __u32 KSU_IOCTL_PROVENANCE_CONTROL =
    _IOWR('K', 33, struct ksu_provenance_control_cmd_v1);
static const __u32 KSU_IOCTL_PROVENANCE_GET_ELIGIBILITY =
    _IOR('K', 34, struct ksu_provenance_eligibility_info_v1);
static const __u32 KSU_IOCTL_PROVENANCE_GET_CONTEXT_STATUS =
    _IOR('K', 35, struct ksu_provenance_context_status_v1);
static const __u32 KSU_IOCTL_PROVENANCE_GET_CURRENT_CONTEXT =
    _IOR('K', 36, struct ksu_provenance_current_context_v1);

#endif /* __KSU_UAPI_PROVENANCE_H */
