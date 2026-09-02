#ifndef __KSU_PROVENANCE_H
#define __KSU_PROVENANCE_H

#include <linux/types.h>

#include "uapi/provenance.h"

int ksu_provenance_init(void);
void ksu_provenance_exit(void);
void ksu_provenance_get_info(struct ksu_provenance_info_v1 *info);
void ksu_provenance_get_context_status(
    struct ksu_provenance_context_status_v1 *status);
int ksu_provenance_get_current_context(
    struct ksu_provenance_current_context_v1 *current_context);

#endif /* __KSU_PROVENANCE_H */
