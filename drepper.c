#ifdef _MSC_VER
#include <malloc.h>
#include <string.h>
#endif

#ifndef HAVE_MEMPCPY
void *mempcpy(void *dest, const void *src, size_t n) {
    memcpy(dest, src, n);
    return (char *)dest + n;
}
#endif

#ifndef HAVE_STPNCPY
char *stpncpy(char *dest, const char *src, size_t n) {
    char * result = strncpy(dest, src, n);
    result += n - 1;
    while (*result == 0 && result > dest) {
        --result;
    }
    ++result;
    return result;
}
#endif

