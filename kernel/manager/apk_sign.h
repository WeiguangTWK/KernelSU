#ifndef __KSU_H_APK_V2_SIGN
#define __KSU_H_APK_V2_SIGN

#include <linux/types.h>

#define KSU_MANAGER_CERT_MAX_LENGTH 4096

bool is_manager_apk(char *path);
int get_pkg_from_apk_path(char *pkg, const char *path);

#endif
