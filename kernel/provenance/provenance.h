#ifndef __KSU_PROVENANCE_H
#define __KSU_PROVENANCE_H

#include <linux/types.h>

#include "uapi/provenance.h"

int ksu_provenance_init(void);
void ksu_provenance_exit(void);
void ksu_provenance_get_info(struct ksu_provenance_info_v1 *info);

#endif /* __KSU_PROVENANCE_H */
