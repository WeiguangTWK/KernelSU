#ifndef __KSU_PROVENANCE_CANONICAL_H
#define __KSU_PROVENANCE_CANONICAL_H

#include <linux/fs.h>
#include <linux/types.h>

#define KSU_PROVENANCE_SHA256_SIZE 32
#define KSU_PROVENANCE_HASH_DOMAIN_SIZE 24

int ksu_provenance_sha256(const void *data, size_t size,
                          u8 digest[KSU_PROVENANCE_SHA256_SIZE]);
int ksu_provenance_sha256_file(struct file *file, u64 expected_size,
                               u8 digest[KSU_PROVENANCE_SHA256_SIZE]);
int ksu_provenance_hash_manifest(const void *manifest, size_t size,
                                 u8 digest[KSU_PROVENANCE_SHA256_SIZE]);
int ksu_provenance_hash_event(const u8 previous[KSU_PROVENANCE_SHA256_SIZE],
                              const void *frame, size_t frame_size,
                              u8 digest[KSU_PROVENANCE_SHA256_SIZE]);

#endif /* __KSU_PROVENANCE_CANONICAL_H */
