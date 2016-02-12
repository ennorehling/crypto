/*
* This is work is derived from material Copyright RSA Data Security, Inc.
*
* The RSA copyright statement and Licence for that original material is
* included below. This is followed by the Apache copyright statement and
* licence for the modifications made to that material.
*/

/* MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
*/

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
*/

/* Copyright 2000-2005 The Apache Software Foundation or its licensors, as
* applicable.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

/*
* The apr_md5_encode() routine uses much code obtained from the FreeBSD 3.0
* MD5 crypt() function, which is licenced as follows:
* ----------------------------------------------------------------------------
* "THE BEER-WARE LICENSE" (Revision 42):
* <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
* can do whatever you want with this stuff. If we meet some day, and you think
* this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
* ----------------------------------------------------------------------------
*/

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"
#include "drepper.h"

#define APR_MD5_DIGESTSIZE 16
typedef md5_state_t apr_md5_ctx_t;
#define apr_md5_init md5_init
#define apr_md5_update md5_append
#define apr_md5_final(final, ctx) md5_finish(ctx, final)
/*
* Define the Magic String prefix that identifies a password as being
* hashed using our algorithm.
*/
static const char *apr1_id = "$apr1$";

static char* apr_cpystrn(char * dst, const char * src, size_t dst_size) {
    return stpncpy(dst, src, dst_size);
}

static void to64(char *s, unsigned long v, int n)
{
    while (--n >= 0) {
        *s++ = itoa64[v & 0x3f];
        v >>= 6;

    }
}

char *apr_md5_encode(const char *pw, const char *salt,
    char *result, size_t nbytes)
{
    /*
    * Minimum size is 8 bytes for salt, plus 1 for the trailing NUL,
    * plus 4 for the '$' separators, plus the password hash itself.
    * Let's leave a goodly amount of leeway.
    */

    char passwd[120], *p;
    const char *sp, *ep;
    unsigned char final[APR_MD5_DIGESTSIZE];
    long sl, pl, i;
    apr_md5_ctx_t ctx, ctx1;
    unsigned long l;

    /*
    * Refine the salt first.  It's possible we were given an already-hashed
    * string as the salt argument, so extract the actual salt value from it
    * if so.  Otherwise just use the string up to the first '$' as the salt.
    */
    sp = salt;

    /*
    * If it starts with the magic string, then skip that.
    */
    if (!strncmp(sp, apr1_id, strlen(apr1_id))) {
        sp += strlen(apr1_id);
    }

    /*
    * It stops at the first '$' or 8 chars, whichever comes first
    */
    for (ep = sp; (*ep != '\0') && (*ep != '$') && (ep < (sp + 8)); ep++) {
        continue;
    }

    /*
    * Get the length of the true salt
    */
    sl = ep - sp;

    /*
    * 'Time to make the doughnuts..'
    */
    apr_md5_init(&ctx);
#if APR_CHARSET_EBCDIC
    apr_md5_set_xlate(&ctx, xlate_ebcdic_to_ascii);
#endif

    /*
    * The password first, since that is what is most unknown
    */
    apr_md5_update(&ctx, pw, strlen(pw));

    /*
    * Then our magic string
    */
    apr_md5_update(&ctx, apr1_id, strlen(apr1_id));

    /*
    * Then the raw salt
    */
    apr_md5_update(&ctx, sp, sl);

    /*
    * Then just as many characters of the MD5(pw, salt, pw)
    */
    apr_md5_init(&ctx1);
    apr_md5_update(&ctx1, pw, strlen(pw));
    apr_md5_update(&ctx1, sp, sl);
    apr_md5_update(&ctx1, pw, strlen(pw));
    apr_md5_final(final, &ctx1);
    for (pl = strlen(pw); pl > 0; pl -= APR_MD5_DIGESTSIZE) {
        apr_md5_update(&ctx, final,
            (pl > APR_MD5_DIGESTSIZE) ? APR_MD5_DIGESTSIZE : pl);
    }

    /*
    * Don't leave anything around in vm they could use.
    */
    memset(final, 0, sizeof(final));

    /*
    * Then something really weird...
    */
    for (i = strlen(pw); i != 0; i >>= 1) {
        if (i & 1) {
            apr_md5_update(&ctx, final, 1);
        }
        else {
            apr_md5_update(&ctx, pw, 1);
        }
    }

    /*
    * Now make the output string.  We know our limitations, so we
    * can use the string routines without bounds checking.
    */
    strcpy(passwd, apr1_id);
    strncat(passwd, sp, sl);
    strcat(passwd, "$");

    apr_md5_final(final, &ctx);

    /*
    * And now, just to make sure things don't run too fast..
    * On a 60 Mhz Pentium this takes 34 msec, so you would
    * need 30 seconds to build a 1000 entry dictionary...
    */
    for (i = 0; i < 1000; i++) {
        apr_md5_init(&ctx1);
        if (i & 1) {
            apr_md5_update(&ctx1, pw, strlen(pw));
        }
        else {
            apr_md5_update(&ctx1, final, APR_MD5_DIGESTSIZE);
        }
        if (i % 3) {
            apr_md5_update(&ctx1, sp, sl);
        }

        if (i % 7) {
            apr_md5_update(&ctx1, pw, strlen(pw));
        }

        if (i & 1) {
            apr_md5_update(&ctx1, final, APR_MD5_DIGESTSIZE);
        }
        else {
            apr_md5_update(&ctx1, pw, strlen(pw));
        }
        apr_md5_final(final, &ctx1);
    }

    p = passwd + strlen(passwd);

    l = (final[0] << 16) | (final[6] << 8) | final[12]; to64(p, l, 4); p += 4;
    l = (final[1] << 16) | (final[7] << 8) | final[13]; to64(p, l, 4); p += 4;
    l = (final[2] << 16) | (final[8] << 8) | final[14]; to64(p, l, 4); p += 4;
    l = (final[3] << 16) | (final[9] << 8) | final[15]; to64(p, l, 4); p += 4;
    l = (final[4] << 16) | (final[10] << 8) | final[5]; to64(p, l, 4); p += 4;
    l = final[11]; to64(p, l, 2); p += 2;
    *p = '\0';

    /*
    * Don't leave anything around in vm they could use.
    */
    memset(final, 0, sizeof(final));

    apr_cpystrn(result, passwd, nbytes);
    return result;
}

