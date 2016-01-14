#include <stddef.h>

#ifndef _MSC_VER
/* probably a gcc derivation */
#define HAVE_MEMPCPY
#define HAVE_STPNCPY
#endif

#ifndef HAVE_MEMPCPY
void *mempcpy(void *dest, const void *src, size_t n);
#endif

#ifndef HAVE_STPNCPY
char *stpncpy(char *dest, const char *src, size_t n);
#endif

