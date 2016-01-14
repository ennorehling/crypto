#include <stddef.h>

#ifndef HAVE_MEMPCPY
void *mempcpy(void *dest, const void *src, size_t n);
#endif

#ifndef HAVE_STPNCPY
char *stpncpy(char *dest, const char *src, size_t n);
#endif

