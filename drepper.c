#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#include <malloc.h>
#endif
#include <string.h>
#include <stddef.h>

#include "drepper.h"

#ifndef HAVE_MEMPCPY
void *mempcpy(void *dest, const void *src, size_t n) {
    memcpy(dest, src, n);
    return (char *)dest + n;
}
#endif

#ifndef HAVE_STPNCPY
char *__stpncpy(char *dst, const char *src, size_t dst_size) {
    size_t len = strlen(src);
    if (len > dst_size) len = dst_size;
    memcpy(dst, src, len);
    dst[len] = 0;
    return dst + len;
}
#endif
