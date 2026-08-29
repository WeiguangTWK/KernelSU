#ifndef __KSU_PROVENANCE_PROVIDER_LSM_H
#define __KSU_PROVENANCE_PROVIDER_LSM_H

#include <linux/types.h>

int ksu_provenance_provider_lsm_init(void);
void ksu_provenance_provider_lsm_exit(void);
void ksu_provenance_provider_lsm_diagnostics(u32 *state, u32 *error,
                                              u64 *capabilities);

#endif /* __KSU_PROVENANCE_PROVIDER_LSM_H */
