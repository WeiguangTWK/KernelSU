#include <crypto/internal/rsa.h>
#include <crypto/public_key.h>
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif

#include "x509_parser.h"

#include "provenance/canonical.h"
#include "provenance/image_verify.h"

#define KSU_PROVENANCE_MAX_KEYS 2
#define KSU_PROVENANCE_RSA3072_DER_MODULUS_SIZE 385

struct ksu_provenance_embedded_key {
    const u8 *certificate_der;
    size_t certificate_size;
    u8 key_id[32];
    u64 minimum_security_epoch;
    const u8 *selftest_image;
    size_t selftest_image_size;
    const u8 *selftest_sidecar;
    size_t selftest_sidecar_size;
};

#ifdef KSU_PROVENANCE_KEY_HEADER
#include KSU_PROVENANCE_KEY_HEADER
#if KSU_PROVENANCE_KEY_HEADER_FORMAT != 2
#error "unsupported provenance key header format; regenerate the public header"
#endif
MODULE_INFO(ksu_provenance_key_header_format, "2");
MODULE_INFO(ksu_provenance_key_ids, KSU_PROVENANCE_EMBEDDED_KEY_IDS_HEX);
MODULE_INFO(ksu_provenance_minimum_epochs, KSU_PROVENANCE_EMBEDDED_MINIMUM_EPOCHS);
#else
static const struct ksu_provenance_embedded_key ksu_provenance_embedded_keys[1];
#define KSU_PROVENANCE_EMBEDDED_KEY_COUNT 0
#endif

struct ksu_provenance_runtime_key {
    struct x509_certificate *certificate;
    const struct ksu_provenance_embedded_key *embedded;
};

struct ksu_provenance_parsed_manifest {
    u32 roles;
    u32 uapi_min;
    u32 uapi_max;
    u64 security_epoch;
    u64 image_size;
    const u8 *image_sha256;
    const u8 *build_id;
    const u8 *signing_key_id;
};

static struct ksu_provenance_runtime_key ksu_provenance_runtime_keys[KSU_PROVENANCE_MAX_KEYS];
static u32 ksu_provenance_verifier_state = KSU_PROVENANCE_VERIFIER_NOT_CONFIGURED;
static atomic_t ksu_provenance_last_error = ATOMIC_INIT(KSU_PROVENANCE_VERIFY_NO_KEY);

static const u8 ksu_provenance_manifest_magic[8] = { 'K', 'S', 'U', 'I', 'M', 'V', '1', 0 };

static bool ksu_provenance_all_zero(const u8 *data, size_t size)
{
    size_t index;

    for (index = 0; index < size; index++) {
        if (data[index])
            return false;
    }
    return true;
}

static bool ksu_provenance_normalize_rsa3072_modulus(const u8 **modulus, size_t *modulus_size)
{
    if (!modulus || !*modulus || !modulus_size)
        return false;

    /*
     * rsa_parse_pub_key() preserves the DER INTEGER value verbatim. A
     * 3072-bit positive modulus therefore has one required 0x00 sign octet
     * followed by exactly 384 bytes whose high bit is set.
     */
    if (*modulus_size != KSU_PROVENANCE_RSA3072_SIGNATURE_SIZE + 1 || (*modulus)[0] != 0 || !((*modulus)[1] & 0x80))
        return false;

    (*modulus)++;
    (*modulus_size)--;
    return true;
}

static bool ksu_provenance_rsa3072_modulus_selftest(void)
{
    static const u8 valid[KSU_PROVENANCE_RSA3072_DER_MODULUS_SIZE] = {
        [1] = 0x80,
        [KSU_PROVENANCE_RSA3072_DER_MODULUS_SIZE - 1] = 1,
    };
    static const u8 noncanonical[KSU_PROVENANCE_RSA3072_DER_MODULUS_SIZE] = {
        [0] = 1,
        [1] = 0x80,
    };
    static const u8 short_modulus[KSU_PROVENANCE_RSA3072_DER_MODULUS_SIZE] = {
        [1] = 0x7f,
    };
    const u8 *modulus = valid;
    size_t modulus_size = sizeof(valid);

    if (!ksu_provenance_normalize_rsa3072_modulus(&modulus, &modulus_size) || modulus != valid + 1 ||
        modulus_size != KSU_PROVENANCE_RSA3072_SIGNATURE_SIZE)
        return false;

    modulus = valid + 1;
    modulus_size = sizeof(valid) - 1;
    if (ksu_provenance_normalize_rsa3072_modulus(&modulus, &modulus_size))
        return false;

    modulus = noncanonical;
    modulus_size = sizeof(noncanonical);
    if (ksu_provenance_normalize_rsa3072_modulus(&modulus, &modulus_size))
        return false;

    modulus = short_modulus;
    modulus_size = sizeof(short_modulus);
    return !ksu_provenance_normalize_rsa3072_modulus(&modulus, &modulus_size);
}

static int ksu_provenance_reject(struct ksu_provenance_verified_image *verified, u32 reason, int error)
{
    atomic_set(&ksu_provenance_last_error, reason);
    if (verified)
        verified->error = reason;
    return error;
}

static int ksu_provenance_validate_certificate(struct ksu_provenance_runtime_key *runtime,
                                               const struct ksu_provenance_embedded_key *embedded)
{
    struct rsa_key rsa = { 0 };
    struct x509_certificate *certificate;
    const u8 *modulus;
    size_t modulus_size;
    u8 digest[32];
    int error;

    error = ksu_provenance_sha256(embedded->certificate_der, embedded->certificate_size, digest);
    if (error)
        return KSU_PROVENANCE_VERIFY_CRYPTO;
    if (memcmp(digest, embedded->key_id, sizeof(digest)))
        return KSU_PROVENANCE_VERIFY_CERT_KEY_ID;

    certificate = x509_cert_parse(embedded->certificate_der, embedded->certificate_size);
    if (IS_ERR(certificate))
        return KSU_PROVENANCE_VERIFY_CERT_PARSE;
    if (!certificate->pub || !certificate->pub->pkey_algo || strcmp(certificate->pub->pkey_algo, "rsa")) {
        x509_free_certificate(certificate);
        return KSU_PROVENANCE_VERIFY_CERT_KEY;
    }

    error = rsa_parse_pub_key(&rsa, certificate->pub->key, certificate->pub->keylen);
    modulus = rsa.n;
    modulus_size = rsa.n_sz;
    if (error || !ksu_provenance_normalize_rsa3072_modulus(&modulus, &modulus_size)) {
        x509_free_certificate(certificate);
        return KSU_PROVENANCE_VERIFY_CERT_KEY;
    }

    runtime->certificate = certificate;
    runtime->embedded = embedded;
    return KSU_PROVENANCE_VERIFY_OK;
}

static u32 ksu_provenance_verifier_selftest(const struct ksu_provenance_runtime_key *key);

int ksu_provenance_image_verifier_init(void)
{
    unsigned int index;
    int reason;

    if (!ksu_provenance_rsa3072_modulus_selftest()) {
        ksu_provenance_verifier_state = KSU_PROVENANCE_VERIFIER_FAILED;
        atomic_set(&ksu_provenance_last_error, KSU_PROVENANCE_VERIFY_INTERNAL);
        return -EINVAL;
    }

    if (!KSU_PROVENANCE_EMBEDDED_KEY_COUNT) {
        ksu_provenance_verifier_state = KSU_PROVENANCE_VERIFIER_NOT_CONFIGURED;
        atomic_set(&ksu_provenance_last_error, KSU_PROVENANCE_VERIFY_NO_KEY);
        return 0;
    }
    if (KSU_PROVENANCE_EMBEDDED_KEY_COUNT > KSU_PROVENANCE_MAX_KEYS) {
        ksu_provenance_verifier_state = KSU_PROVENANCE_VERIFIER_FAILED;
        atomic_set(&ksu_provenance_last_error, KSU_PROVENANCE_VERIFY_INTERNAL);
        return -E2BIG;
    }

    for (index = 0; index < KSU_PROVENANCE_EMBEDDED_KEY_COUNT; index++) {
        reason = ksu_provenance_validate_certificate(&ksu_provenance_runtime_keys[index],
                                                     &ksu_provenance_embedded_keys[index]);
        if (reason != KSU_PROVENANCE_VERIFY_OK) {
            ksu_provenance_image_verifier_exit();
            ksu_provenance_verifier_state = KSU_PROVENANCE_VERIFIER_FAILED;
            atomic_set(&ksu_provenance_last_error, reason);
            return -EKEYREJECTED;
        }
    }
    for (index = 0; index < KSU_PROVENANCE_EMBEDDED_KEY_COUNT; index++) {
        reason = ksu_provenance_verifier_selftest(&ksu_provenance_runtime_keys[index]);
        if (reason != KSU_PROVENANCE_VERIFY_OK) {
            ksu_provenance_image_verifier_exit();
            ksu_provenance_verifier_state = KSU_PROVENANCE_VERIFIER_FAILED;
            atomic_set(&ksu_provenance_last_error, reason);
            return -EKEYREJECTED;
        }
    }

    ksu_provenance_verifier_state = KSU_PROVENANCE_VERIFIER_READY;
    atomic_set(&ksu_provenance_last_error, KSU_PROVENANCE_VERIFY_OK);
    return 0;
}

void ksu_provenance_image_verifier_exit(void)
{
    unsigned int index;

    for (index = 0; index < KSU_PROVENANCE_MAX_KEYS; index++) {
        if (ksu_provenance_runtime_keys[index].certificate)
            x509_free_certificate(ksu_provenance_runtime_keys[index].certificate);
        ksu_provenance_runtime_keys[index].certificate = NULL;
        ksu_provenance_runtime_keys[index].embedded = NULL;
    }
}

static const struct ksu_provenance_runtime_key *ksu_provenance_find_key(const u8 key_id[32])
{
    unsigned int index;

    for (index = 0; index < KSU_PROVENANCE_EMBEDDED_KEY_COUNT; index++) {
        if (!memcmp(key_id, ksu_provenance_runtime_keys[index].embedded->key_id, 32))
            return &ksu_provenance_runtime_keys[index];
    }
    return NULL;
}

static int ksu_provenance_read_sidecar(const char *path, u8 **sidecar, struct ksu_provenance_verified_image *verified)
{
    struct file *file;
    loff_t position = 0;
    ssize_t count;

    file = filp_open(path, O_RDONLY | O_NOFOLLOW, 0);
    if (IS_ERR(file))
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_SIDECAR_OPEN, PTR_ERR(file));
    if (!S_ISREG(file_inode(file)->i_mode)) {
        filp_close(file, NULL);
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_SIDECAR_TYPE, -EINVAL);
    }
    if (i_size_read(file_inode(file)) != KSU_PROVENANCE_SIDECAR_SIZE_V1) {
        filp_close(file, NULL);
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_SIDECAR_SIZE, -EMSGSIZE);
    }

    *sidecar = kmalloc(KSU_PROVENANCE_SIDECAR_SIZE_V1, GFP_KERNEL);
    if (!*sidecar) {
        filp_close(file, NULL);
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_INTERNAL, -ENOMEM);
    }
    count = kernel_read(file, *sidecar, KSU_PROVENANCE_SIDECAR_SIZE_V1, &position);
    filp_close(file, NULL);
    if (count != KSU_PROVENANCE_SIDECAR_SIZE_V1) {
        kfree(*sidecar);
        *sidecar = NULL;
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_SIDECAR_READ, count < 0 ? (int)count : -EIO);
    }
    return 0;
}

static int ksu_provenance_parse_manifest(const u8 *manifest, u32 required_role,
                                         struct ksu_provenance_parsed_manifest *parsed,
                                         struct ksu_provenance_verified_image *verified)
{
    if (memcmp(manifest, ksu_provenance_manifest_magic, sizeof(ksu_provenance_manifest_magic)))
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_MANIFEST_MAGIC, -EBADMSG);
    if (get_unaligned_le16(manifest + 8) != KSU_PROVENANCE_MANIFEST_FORMAT_VERSION)
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_MANIFEST_VERSION, -EPROTONOSUPPORT);
    if (get_unaligned_le16(manifest + 10) != KSU_PROVENANCE_MANIFEST_SIZE_V1)
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_MANIFEST_LENGTH, -EMSGSIZE);
    if (get_unaligned_le32(manifest + 12))
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_MANIFEST_FLAGS, -EINVAL);
    if (get_unaligned_le32(manifest + 20) || !ksu_provenance_all_zero(manifest + 144, 48))
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_MANIFEST_RESERVED, -EINVAL);

    parsed->roles = get_unaligned_le32(manifest + 16);
    if (!parsed->roles || (parsed->roles & ~KSU_PROVENANCE_ROLE_MASK_V1) ||
        (required_role && !(parsed->roles & required_role)))
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_ROLE, -EACCES);

    parsed->image_size = get_unaligned_le64(manifest + 24);
    parsed->image_sha256 = manifest + 32;
    parsed->build_id = manifest + 64;
    parsed->uapi_min = get_unaligned_le32(manifest + 96);
    parsed->uapi_max = get_unaligned_le32(manifest + 100);
    parsed->security_epoch = get_unaligned_le64(manifest + 104);
    parsed->signing_key_id = manifest + 112;

    if (!parsed->uapi_min || parsed->uapi_min > parsed->uapi_max || parsed->uapi_min > KSU_PROVENANCE_UAPI_VERSION ||
        parsed->uapi_max < KSU_PROVENANCE_UAPI_VERSION)
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_UAPI, -EPROTONOSUPPORT);
    if (ksu_provenance_all_zero(parsed->build_id, 32))
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_MANIFEST_RESERVED, -EINVAL);
    return 0;
}

static int ksu_provenance_verify_manifest_signature(const struct ksu_provenance_runtime_key *key, const u8 *manifest,
                                                    const u8 *signature, struct ksu_provenance_verified_image *verified)
{
    struct public_key_signature public_signature = { 0 };
    u8 digest[32];
    int error;

    error = ksu_provenance_hash_manifest(manifest, KSU_PROVENANCE_MANIFEST_SIZE_V1, digest);
    if (error)
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_CRYPTO, error);

    public_signature.s = (u8 *)signature;
    public_signature.s_size = KSU_PROVENANCE_RSA3072_SIGNATURE_SIZE;
    public_signature.digest = digest;
    public_signature.digest_size = sizeof(digest);
    public_signature.pkey_algo = "rsa";
    public_signature.hash_algo = "sha256";
    public_signature.encoding = "pkcs1";

    error = public_key_verify_signature(key->certificate->pub, &public_signature);
    if (error)
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_SIGNATURE, -EKEYREJECTED);
    return 0;
}

static int ksu_provenance_verify_selftest_material(const struct ksu_provenance_runtime_key *key, const u8 *sidecar,
                                                   size_t sidecar_size, const u8 *image, size_t image_size,
                                                   u32 required_role, struct ksu_provenance_verified_image *verified)
{
    struct ksu_provenance_parsed_manifest parsed = { 0 };
    u8 digest[32];
    int error;

    memset(verified, 0, sizeof(*verified));
    if (!sidecar || sidecar_size != KSU_PROVENANCE_SIDECAR_SIZE_V1)
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_SIDECAR_SIZE, -EMSGSIZE);
    if (!image || !image_size || !required_role || (required_role & ~KSU_PROVENANCE_ROLE_MASK_V1))
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_ROLE, -EINVAL);

    error = ksu_provenance_parse_manifest(sidecar, required_role, &parsed, verified);
    if (error)
        return error;
    if (memcmp(parsed.signing_key_id, key->embedded->key_id, 32))
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_KEY_ID, -ENOKEY);
    if (parsed.security_epoch < key->embedded->minimum_security_epoch)
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_EPOCH, -EKEYREJECTED);
    if (!parsed.image_size || parsed.image_size > KSU_PROVENANCE_MAX_IMAGE_SIZE || parsed.image_size != image_size)
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_IMAGE_SIZE, -EFBIG);

    error = ksu_provenance_verify_manifest_signature(key, sidecar, sidecar + KSU_PROVENANCE_MANIFEST_SIZE_V1, verified);
    if (error)
        return error;
    error = ksu_provenance_sha256(image, image_size, digest);
    if (error)
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_CRYPTO, error);
    if (memcmp(digest, parsed.image_sha256, sizeof(digest)))
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_IMAGE_DIGEST, -EKEYREJECTED);

    verified->roles = parsed.roles;
    verified->uapi_min = parsed.uapi_min;
    verified->uapi_max = parsed.uapi_max;
    verified->security_epoch = parsed.security_epoch;
    verified->image_size = parsed.image_size;
    memcpy(verified->image_sha256, parsed.image_sha256, 32);
    memcpy(verified->build_id, parsed.build_id, 32);
    memcpy(verified->signing_key_id, parsed.signing_key_id, 32);
    verified->error = KSU_PROVENANCE_VERIFY_OK;
    return 0;
}

static bool ksu_provenance_selftest_rejects(const struct ksu_provenance_runtime_key *key, const u8 *sidecar,
                                            size_t sidecar_size, const u8 *image, size_t image_size, u32 required_role,
                                            u32 expected_reason)
{
    struct ksu_provenance_verified_image verified;
    int error;

    error = ksu_provenance_verify_selftest_material(key, sidecar, sidecar_size, image, image_size, required_role,
                                                    &verified);
    return error && verified.error == expected_reason;
}

static u32 ksu_provenance_verifier_selftest(const struct ksu_provenance_runtime_key *key)
{
    const struct ksu_provenance_embedded_key *embedded = key->embedded;
    struct ksu_provenance_verified_image verified;
    u8 *sidecar;
    u8 *image;
    int error;

    if (!embedded->selftest_image || !embedded->selftest_image_size || !embedded->selftest_sidecar ||
        embedded->selftest_sidecar_size != KSU_PROVENANCE_SIDECAR_SIZE_V1)
        return KSU_PROVENANCE_VERIFY_INTERNAL;

    error = ksu_provenance_verify_selftest_material(key, embedded->selftest_sidecar, embedded->selftest_sidecar_size,
                                                    embedded->selftest_image, embedded->selftest_image_size,
                                                    KSU_PROVENANCE_ROLE_SUPERVISOR, &verified);
    if (error)
        return verified.error ?: KSU_PROVENANCE_VERIFY_INTERNAL;

    if (!ksu_provenance_selftest_rejects(key, embedded->selftest_sidecar, embedded->selftest_sidecar_size - 1,
                                         embedded->selftest_image, embedded->selftest_image_size,
                                         KSU_PROVENANCE_ROLE_SUPERVISOR, KSU_PROVENANCE_VERIFY_SIDECAR_SIZE) ||
        !ksu_provenance_selftest_rejects(key, embedded->selftest_sidecar, embedded->selftest_sidecar_size + 1,
                                         embedded->selftest_image, embedded->selftest_image_size,
                                         KSU_PROVENANCE_ROLE_SUPERVISOR, KSU_PROVENANCE_VERIFY_SIDECAR_SIZE) ||
        !ksu_provenance_selftest_rejects(key, embedded->selftest_sidecar, embedded->selftest_sidecar_size,
                                         embedded->selftest_image, embedded->selftest_image_size,
                                         KSU_PROVENANCE_ROLE_INIT_PROXY, KSU_PROVENANCE_VERIFY_ROLE) ||
        !ksu_provenance_selftest_rejects(key, embedded->selftest_sidecar, embedded->selftest_sidecar_size,
                                         embedded->selftest_image, embedded->selftest_image_size - 1,
                                         KSU_PROVENANCE_ROLE_SUPERVISOR, KSU_PROVENANCE_VERIFY_IMAGE_SIZE))
        return KSU_PROVENANCE_VERIFY_INTERNAL;

    sidecar = kmalloc(embedded->selftest_sidecar_size, GFP_KERNEL);
    image = kmalloc(embedded->selftest_image_size, GFP_KERNEL);
    if (!sidecar || !image) {
        kfree(sidecar);
        kfree(image);
        return KSU_PROVENANCE_VERIFY_INTERNAL;
    }
    memcpy(sidecar, embedded->selftest_sidecar, embedded->selftest_sidecar_size);
    memcpy(image, embedded->selftest_image, embedded->selftest_image_size);

#define KSU_PROVENANCE_EXPECT_MUTATION(offset, reason)                                                                 \
    do {                                                                                                               \
        memcpy(sidecar, embedded->selftest_sidecar, embedded->selftest_sidecar_size);                                  \
        sidecar[(offset)] ^= 1;                                                                                        \
        if (!ksu_provenance_selftest_rejects(key, sidecar, embedded->selftest_sidecar_size, embedded->selftest_image,  \
                                             embedded->selftest_image_size, KSU_PROVENANCE_ROLE_SUPERVISOR,            \
                                             (reason))) {                                                              \
            error = KSU_PROVENANCE_VERIFY_INTERNAL;                                                                    \
            goto out;                                                                                                  \
        }                                                                                                              \
    } while (0)

    KSU_PROVENANCE_EXPECT_MUTATION(0, KSU_PROVENANCE_VERIFY_MANIFEST_MAGIC);
    KSU_PROVENANCE_EXPECT_MUTATION(8, KSU_PROVENANCE_VERIFY_MANIFEST_VERSION);
    KSU_PROVENANCE_EXPECT_MUTATION(10, KSU_PROVENANCE_VERIFY_MANIFEST_LENGTH);
    KSU_PROVENANCE_EXPECT_MUTATION(12, KSU_PROVENANCE_VERIFY_MANIFEST_FLAGS);
    KSU_PROVENANCE_EXPECT_MUTATION(20, KSU_PROVENANCE_VERIFY_MANIFEST_RESERVED);
    KSU_PROVENANCE_EXPECT_MUTATION(144, KSU_PROVENANCE_VERIFY_MANIFEST_RESERVED);
    KSU_PROVENANCE_EXPECT_MUTATION(112, KSU_PROVENANCE_VERIFY_KEY_ID);
    KSU_PROVENANCE_EXPECT_MUTATION(KSU_PROVENANCE_MANIFEST_SIZE_V1, KSU_PROVENANCE_VERIFY_SIGNATURE);

    memcpy(sidecar, embedded->selftest_sidecar, embedded->selftest_sidecar_size);
    put_unaligned_le32(KSU_PROVENANCE_UAPI_VERSION + 1, sidecar + 96);
    put_unaligned_le32(KSU_PROVENANCE_UAPI_VERSION + 1, sidecar + 100);
    if (!ksu_provenance_selftest_rejects(key, sidecar, embedded->selftest_sidecar_size, embedded->selftest_image,
                                         embedded->selftest_image_size, KSU_PROVENANCE_ROLE_SUPERVISOR,
                                         KSU_PROVENANCE_VERIFY_UAPI)) {
        error = KSU_PROVENANCE_VERIFY_INTERNAL;
        goto out;
    }

    memcpy(sidecar, embedded->selftest_sidecar, embedded->selftest_sidecar_size);
    put_unaligned_le64(0, sidecar + 104);
    if (!ksu_provenance_selftest_rejects(key, sidecar, embedded->selftest_sidecar_size, embedded->selftest_image,
                                         embedded->selftest_image_size, KSU_PROVENANCE_ROLE_SUPERVISOR,
                                         KSU_PROVENANCE_VERIFY_EPOCH)) {
        error = KSU_PROVENANCE_VERIFY_INTERNAL;
        goto out;
    }

    image[0] ^= 1;
    if (!ksu_provenance_selftest_rejects(key, embedded->selftest_sidecar, embedded->selftest_sidecar_size, image,
                                         embedded->selftest_image_size, KSU_PROVENANCE_ROLE_SUPERVISOR,
                                         KSU_PROVENANCE_VERIFY_IMAGE_DIGEST)) {
        error = KSU_PROVENANCE_VERIFY_INTERNAL;
        goto out;
    }

    error = KSU_PROVENANCE_VERIFY_OK;
out:
    kfree(sidecar);
    kfree(image);
#undef KSU_PROVENANCE_EXPECT_MUTATION
    return error;
}

int ksu_provenance_verify_image(struct file *image, const char *sidecar_path, u32 required_role,
                                struct ksu_provenance_verified_image *verified)
{
    const struct ksu_provenance_runtime_key *key;
    struct ksu_provenance_parsed_manifest parsed;
    u8 actual_digest[32];
    u8 *sidecar = NULL;
    int error;

    if (!verified)
        return -EINVAL;
    memset(verified, 0, sizeof(*verified));
    memset(&parsed, 0, sizeof(parsed));

    if (ksu_provenance_verifier_state != KSU_PROVENANCE_VERIFIER_READY) {
        u32 reason = ksu_provenance_verifier_state == KSU_PROVENANCE_VERIFIER_FAILED ?
                         atomic_read(&ksu_provenance_last_error) :
                         KSU_PROVENANCE_VERIFY_NO_KEY;

        if (verified)
            verified->error = reason;
        return -ENOKEY;
    }
    if (!image || !sidecar_path)
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_INTERNAL, -EINVAL);
    if (!S_ISREG(file_inode(image)->i_mode))
        return ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_IMAGE_TYPE, -EINVAL);

    error = ksu_provenance_read_sidecar(sidecar_path, &sidecar, verified);
    if (error)
        return error;
    if (!required_role || (required_role & ~KSU_PROVENANCE_ROLE_MASK_V1)) {
        error = ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_ROLE, -EINVAL);
        goto out;
    }
    error = ksu_provenance_parse_manifest(sidecar, required_role, &parsed, verified);
    if (error)
        goto out;

    key = ksu_provenance_find_key(parsed.signing_key_id);
    if (!key) {
        error = ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_KEY_ID, -ENOKEY);
        goto out;
    }
    if (parsed.security_epoch < key->embedded->minimum_security_epoch) {
        error = ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_EPOCH, -EKEYREJECTED);
        goto out;
    }
    if (!parsed.image_size || parsed.image_size > KSU_PROVENANCE_MAX_IMAGE_SIZE ||
        parsed.image_size != i_size_read(file_inode(image))) {
        error = ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_IMAGE_SIZE, -EFBIG);
        goto out;
    }

    error = ksu_provenance_verify_manifest_signature(key, sidecar, sidecar + KSU_PROVENANCE_MANIFEST_SIZE_V1, verified);
    if (error)
        goto out;
    error = ksu_provenance_sha256_file(image, parsed.image_size, actual_digest);
    if (error) {
        error = ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_IMAGE_READ, error);
        goto out;
    }
    if (memcmp(actual_digest, parsed.image_sha256, sizeof(actual_digest))) {
        error = ksu_provenance_reject(verified, KSU_PROVENANCE_VERIFY_IMAGE_DIGEST, -EKEYREJECTED);
        goto out;
    }

    verified->roles = parsed.roles;
    verified->uapi_min = parsed.uapi_min;
    verified->uapi_max = parsed.uapi_max;
    verified->security_epoch = parsed.security_epoch;
    verified->image_size = parsed.image_size;
    memcpy(verified->image_sha256, parsed.image_sha256, 32);
    memcpy(verified->build_id, parsed.build_id, 32);
    memcpy(verified->signing_key_id, parsed.signing_key_id, 32);
    verified->error = KSU_PROVENANCE_VERIFY_OK;
    atomic_set(&ksu_provenance_last_error, KSU_PROVENANCE_VERIFY_OK);
    error = 0;
out:
    kfree(sidecar);
    return error;
}

void ksu_provenance_image_verifier_diagnostics(u32 *state, u32 *error, u64 *minimum_epoch, u8 key_id[32],
                                               u64 *capabilities)
{
    *state = ksu_provenance_verifier_state;
    *error = atomic_read(&ksu_provenance_last_error);
    *minimum_epoch = 0;
    memset(key_id, 0, 32);
    *capabilities = KSU_PROVENANCE_CAP_IMAGE_VERIFIER_V1;

    if (KSU_PROVENANCE_EMBEDDED_KEY_COUNT) {
        *minimum_epoch = ksu_provenance_embedded_keys[0].minimum_security_epoch;
        memcpy(key_id, ksu_provenance_embedded_keys[0].key_id, 32);
    }
    if (ksu_provenance_verifier_state == KSU_PROVENANCE_VERIFIER_READY)
        *capabilities |= KSU_PROVENANCE_CAP_SIGNING_KEY_V1;
}
