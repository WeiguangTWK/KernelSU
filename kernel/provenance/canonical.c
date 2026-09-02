#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include "provenance/canonical.h"
#include "uapi/provenance.h"

struct ksu_provenance_shash_desc {
    struct shash_desc shash;
    u8 context[];
};

static const u8 ksu_provenance_manifest_domain[KSU_PROVENANCE_HASH_DOMAIN_SIZE] =
    "KSU-PROVENANCE-IMAGE-V1";
static const u8 ksu_provenance_event_domain[KSU_PROVENANCE_HASH_DOMAIN_SIZE] =
    "KSU-PROVENANCE-EVENT-V1";

static struct ksu_provenance_shash_desc *ksu_provenance_alloc_sha256(struct crypto_shash **algorithm)
{
    struct ksu_provenance_shash_desc *descriptor;
    size_t size;

    *algorithm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(*algorithm))
        return ERR_CAST(*algorithm);

    size = sizeof(*descriptor) + crypto_shash_descsize(*algorithm);
    descriptor = kzalloc(size, GFP_KERNEL);
    if (!descriptor) {
        crypto_free_shash(*algorithm);
        return ERR_PTR(-ENOMEM);
    }
    descriptor->shash.tfm = *algorithm;
    return descriptor;
}

static void ksu_provenance_free_sha256(struct crypto_shash *algorithm,
                                       struct ksu_provenance_shash_desc *descriptor)
{
    kfree(descriptor);
    crypto_free_shash(algorithm);
}

int ksu_provenance_sha256(const void *data, size_t size,
                          u8 digest[KSU_PROVENANCE_SHA256_SIZE])
{
    struct ksu_provenance_shash_desc *descriptor;
    struct crypto_shash *algorithm;
    int error;

    descriptor = ksu_provenance_alloc_sha256(&algorithm);
    if (IS_ERR(descriptor))
        return PTR_ERR(descriptor);

    error = crypto_shash_digest(&descriptor->shash, data, size, digest);
    ksu_provenance_free_sha256(algorithm, descriptor);
    return error;
}

int ksu_provenance_sha256_file(struct file *file, u64 expected_size,
                               u8 digest[KSU_PROVENANCE_SHA256_SIZE])
{
    struct ksu_provenance_shash_desc *descriptor;
    struct crypto_shash *algorithm;
    loff_t position = 0;
    u64 remaining = expected_size;
    u8 *buffer;
    int error;

    if (!file || expected_size > KSU_PROVENANCE_MAX_IMAGE_SIZE)
        return -EFBIG;

    descriptor = ksu_provenance_alloc_sha256(&algorithm);
    if (IS_ERR(descriptor))
        return PTR_ERR(descriptor);

    buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buffer) {
        error = -ENOMEM;
        goto out_descriptor;
    }

    error = crypto_shash_init(&descriptor->shash);
    while (!error && remaining) {
        size_t requested = min_t(u64, remaining, PAGE_SIZE);
        ssize_t count = kernel_read(file, buffer, requested, &position);

        if (count != (ssize_t)requested) {
            error = count < 0 ? (int)count : -EIO;
            break;
        }
        error = crypto_shash_update(&descriptor->shash, buffer, requested);
        remaining -= requested;
    }
    if (!error)
        error = crypto_shash_final(&descriptor->shash, digest);

    kfree(buffer);
out_descriptor:
    ksu_provenance_free_sha256(algorithm, descriptor);
    return error;
}

static int ksu_provenance_hash_parts(const u8 domain[KSU_PROVENANCE_HASH_DOMAIN_SIZE],
                                     const void *prefix, size_t prefix_size,
                                     const void *data, size_t data_size,
                                     u8 digest[KSU_PROVENANCE_SHA256_SIZE])
{
    struct ksu_provenance_shash_desc *descriptor;
    struct crypto_shash *algorithm;
    int error;

    descriptor = ksu_provenance_alloc_sha256(&algorithm);
    if (IS_ERR(descriptor))
        return PTR_ERR(descriptor);

    error = crypto_shash_init(&descriptor->shash);
    if (!error)
        error = crypto_shash_update(&descriptor->shash, domain,
                                    KSU_PROVENANCE_HASH_DOMAIN_SIZE);
    if (!error && prefix_size)
        error = crypto_shash_update(&descriptor->shash, prefix, prefix_size);
    if (!error)
        error = crypto_shash_update(&descriptor->shash, data, data_size);
    if (!error)
        error = crypto_shash_final(&descriptor->shash, digest);

    ksu_provenance_free_sha256(algorithm, descriptor);
    return error;
}

int ksu_provenance_hash_manifest(const void *manifest, size_t size,
                                 u8 digest[KSU_PROVENANCE_SHA256_SIZE])
{
    return ksu_provenance_hash_parts(ksu_provenance_manifest_domain, NULL, 0,
                                     manifest, size, digest);
}

int ksu_provenance_hash_event(const u8 previous[KSU_PROVENANCE_SHA256_SIZE],
                              const void *frame, size_t frame_size,
                              u8 digest[KSU_PROVENANCE_SHA256_SIZE])
{
    return ksu_provenance_hash_parts(ksu_provenance_event_domain, previous,
                                     KSU_PROVENANCE_SHA256_SIZE, frame,
                                     frame_size, digest);
}
