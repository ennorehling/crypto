/*
  Copyright (C) 1999, 2000, 2002 Aladdin Enterprises.  All rights reserved.

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  L. Peter Deutsch
  ghost@aladdin.com

 */
/* $Id: md5.c,v 1.6 2002/04/13 19:20:28 lpd Exp $ */
/*
  Independent implementation of MD5 (RFC 1321).

  This code implements the MD5 Algorithm defined in RFC 1321, whose
  text is available at
	http://www.ietf.org/rfc/rfc1321.txt
  The code is derived from the text of the RFC, including the test suite
  (section A.5) but excluding the rest of Appendix A.  It does not include
  any code or documentation that is identified in the RFC as being
  copyrighted.

  The original and principal author of md5.c is L. Peter Deutsch
  <ghost@aladdin.com>.  Other authors are noted in the change history
  that follows (in reverse chronological order):

  2002-04-13 lpd Clarified derivation from RFC 1321; now handles byte order
	either statically or dynamically; added missing #include <string.h>
	in library.
  2002-03-11 lpd Corrected argument list for main(), and added int return
	type, in test program and T value program.
  2002-02-21 lpd Added missing #include <stdio.h> in test program.
  2000-07-03 lpd Patched to eliminate warnings about "constant is
	unsigned in ANSI C, signed in traditional"; made test program
	self-checking.
  1999-11-04 lpd Edited comments slightly for automatic TOC extraction.
  1999-10-18 lpd Fixed typo in header comment (ansi2knr rather than md5).
  1999-05-03 lpd Original version.
 */

#include "md5.h"
#include <string.h>

#undef BYTE_ORDER	/* 1 = big-endian, -1 = little-endian, 0 = unknown */
#ifdef ARCH_IS_BIG_ENDIAN
#  define BYTE_ORDER (ARCH_IS_BIG_ENDIAN ? 1 : -1)
#else
#  define BYTE_ORDER 0
#endif

#define T_MASK ((md5_word_t)~0)
#define T1 /* 0xd76aa478 */ (T_MASK ^ 0x28955b87)
#define T2 /* 0xe8c7b756 */ (T_MASK ^ 0x173848a9)
#define T3    0x242070db
#define T4 /* 0xc1bdceee */ (T_MASK ^ 0x3e423111)
#define T5 /* 0xf57c0faf */ (T_MASK ^ 0x0a83f050)
#define T6    0x4787c62a
#define T7 /* 0xa8304613 */ (T_MASK ^ 0x57cfb9ec)
#define T8 /* 0xfd469501 */ (T_MASK ^ 0x02b96afe)
#define T9    0x698098d8
#define T10 /* 0x8b44f7af */ (T_MASK ^ 0x74bb0850)
#define T11 /* 0xffff5bb1 */ (T_MASK ^ 0x0000a44e)
#define T12 /* 0x895cd7be */ (T_MASK ^ 0x76a32841)
#define T13    0x6b901122
#define T14 /* 0xfd987193 */ (T_MASK ^ 0x02678e6c)
#define T15 /* 0xa679438e */ (T_MASK ^ 0x5986bc71)
#define T16    0x49b40821
#define T17 /* 0xf61e2562 */ (T_MASK ^ 0x09e1da9d)
#define T18 /* 0xc040b340 */ (T_MASK ^ 0x3fbf4cbf)
#define T19    0x265e5a51
#define T20 /* 0xe9b6c7aa */ (T_MASK ^ 0x16493855)
#define T21 /* 0xd62f105d */ (T_MASK ^ 0x29d0efa2)
#define T22    0x02441453
#define T23 /* 0xd8a1e681 */ (T_MASK ^ 0x275e197e)
#define T24 /* 0xe7d3fbc8 */ (T_MASK ^ 0x182c0437)
#define T25    0x21e1cde6
#define T26 /* 0xc33707d6 */ (T_MASK ^ 0x3cc8f829)
#define T27 /* 0xf4d50d87 */ (T_MASK ^ 0x0b2af278)
#define T28    0x455a14ed
#define T29 /* 0xa9e3e905 */ (T_MASK ^ 0x561c16fa)
#define T30 /* 0xfcefa3f8 */ (T_MASK ^ 0x03105c07)
#define T31    0x676f02d9
#define T32 /* 0x8d2a4c8a */ (T_MASK ^ 0x72d5b375)
#define T33 /* 0xfffa3942 */ (T_MASK ^ 0x0005c6bd)
#define T34 /* 0x8771f681 */ (T_MASK ^ 0x788e097e)
#define T35    0x6d9d6122
#define T36 /* 0xfde5380c */ (T_MASK ^ 0x021ac7f3)
#define T37 /* 0xa4beea44 */ (T_MASK ^ 0x5b4115bb)
#define T38    0x4bdecfa9
#define T39 /* 0xf6bb4b60 */ (T_MASK ^ 0x0944b49f)
#define T40 /* 0xbebfbc70 */ (T_MASK ^ 0x4140438f)
#define T41    0x289b7ec6
#define T42 /* 0xeaa127fa */ (T_MASK ^ 0x155ed805)
#define T43 /* 0xd4ef3085 */ (T_MASK ^ 0x2b10cf7a)
#define T44    0x04881d05
#define T45 /* 0xd9d4d039 */ (T_MASK ^ 0x262b2fc6)
#define T46 /* 0xe6db99e5 */ (T_MASK ^ 0x1924661a)
#define T47    0x1fa27cf8
#define T48 /* 0xc4ac5665 */ (T_MASK ^ 0x3b53a99a)
#define T49 /* 0xf4292244 */ (T_MASK ^ 0x0bd6ddbb)
#define T50    0x432aff97
#define T51 /* 0xab9423a7 */ (T_MASK ^ 0x546bdc58)
#define T52 /* 0xfc93a039 */ (T_MASK ^ 0x036c5fc6)
#define T53    0x655b59c3
#define T54 /* 0x8f0ccc92 */ (T_MASK ^ 0x70f3336d)
#define T55 /* 0xffeff47d */ (T_MASK ^ 0x00100b82)
#define T56 /* 0x85845dd1 */ (T_MASK ^ 0x7a7ba22e)
#define T57    0x6fa87e4f
#define T58 /* 0xfe2ce6e0 */ (T_MASK ^ 0x01d3191f)
#define T59 /* 0xa3014314 */ (T_MASK ^ 0x5cfebceb)
#define T60    0x4e0811a1
#define T61 /* 0xf7537e82 */ (T_MASK ^ 0x08ac817d)
#define T62 /* 0xbd3af235 */ (T_MASK ^ 0x42c50dca)
#define T63    0x2ad7d2bb
#define T64 /* 0xeb86d391 */ (T_MASK ^ 0x14792c6e)

unsigned char itoa64[64] =         /* 0 ... 63 => ASCII - 64 */
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void
md5_process(md5_state_t *pms, const md5_byte_t *data /*[64]*/)
{
    md5_word_t
	a = pms->abcd[0], b = pms->abcd[1],
	c = pms->abcd[2], d = pms->abcd[3];
    md5_word_t t;
#if BYTE_ORDER > 0
    /* Define storage only for big-endian CPUs. */
    md5_word_t X[16];
#else
    /* Define storage for little-endian or both types of CPUs. */
    md5_word_t xbuf[16];
    const md5_word_t *X;
#endif

    {
#if BYTE_ORDER == 0
	/*
	 * Determine dynamically whether this is a big-endian or
	 * little-endian machine, since we can use a more efficient
	 * algorithm on the latter.
	 */
	static const int w = 1;

	if (*((const md5_byte_t *)&w)) /* dynamic little-endian */
#endif
#if BYTE_ORDER <= 0		/* little-endian */
	{
	    /*
	     * On little-endian machines, we can process properly aligned
	     * data without copying it.
	     */
	    if (!((data - (const md5_byte_t *)0) & 3)) {
		/* data are properly aligned */
		X = (const md5_word_t *)data;
	    } else {
		/* not aligned */
		memcpy(xbuf, data, 64);
		X = xbuf;
	    }
	}
#endif
#if BYTE_ORDER == 0
	else			/* dynamic big-endian */
#endif
#if BYTE_ORDER >= 0		/* big-endian */
	{
	    /*
	     * On big-endian machines, we must arrange the bytes in the
	     * right order.
	     */
	    const md5_byte_t *xp = data;
	    int i;

#  if BYTE_ORDER == 0
	    X = xbuf;		/* (dynamic only) */
#  else
#    define xbuf X		/* (static only) */
#  endif
	    for (i = 0; i < 16; ++i, xp += 4)
		xbuf[i] = xp[0] + (xp[1] << 8) + (xp[2] << 16) + (xp[3] << 24);
	}
#endif
    }

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

    /* Round 1. */
    /* Let [abcd k s i] denote the operation
       a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define SET(a, b, c, d, k, s, Ti)\
  t = a + F(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
    /* Do the following 16 operations. */
    SET(a, b, c, d,  0,  7,  T1);
    SET(d, a, b, c,  1, 12,  T2);
    SET(c, d, a, b,  2, 17,  T3);
    SET(b, c, d, a,  3, 22,  T4);
    SET(a, b, c, d,  4,  7,  T5);
    SET(d, a, b, c,  5, 12,  T6);
    SET(c, d, a, b,  6, 17,  T7);
    SET(b, c, d, a,  7, 22,  T8);
    SET(a, b, c, d,  8,  7,  T9);
    SET(d, a, b, c,  9, 12, T10);
    SET(c, d, a, b, 10, 17, T11);
    SET(b, c, d, a, 11, 22, T12);
    SET(a, b, c, d, 12,  7, T13);
    SET(d, a, b, c, 13, 12, T14);
    SET(c, d, a, b, 14, 17, T15);
    SET(b, c, d, a, 15, 22, T16);
#undef SET

     /* Round 2. */
     /* Let [abcd k s i] denote the operation
          a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s). */
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define SET(a, b, c, d, k, s, Ti)\
  t = a + G(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
     /* Do the following 16 operations. */
    SET(a, b, c, d,  1,  5, T17);
    SET(d, a, b, c,  6,  9, T18);
    SET(c, d, a, b, 11, 14, T19);
    SET(b, c, d, a,  0, 20, T20);
    SET(a, b, c, d,  5,  5, T21);
    SET(d, a, b, c, 10,  9, T22);
    SET(c, d, a, b, 15, 14, T23);
    SET(b, c, d, a,  4, 20, T24);
    SET(a, b, c, d,  9,  5, T25);
    SET(d, a, b, c, 14,  9, T26);
    SET(c, d, a, b,  3, 14, T27);
    SET(b, c, d, a,  8, 20, T28);
    SET(a, b, c, d, 13,  5, T29);
    SET(d, a, b, c,  2,  9, T30);
    SET(c, d, a, b,  7, 14, T31);
    SET(b, c, d, a, 12, 20, T32);
#undef SET

     /* Round 3. */
     /* Let [abcd k s t] denote the operation
          a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s). */
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define SET(a, b, c, d, k, s, Ti)\
  t = a + H(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
     /* Do the following 16 operations. */
    SET(a, b, c, d,  5,  4, T33);
    SET(d, a, b, c,  8, 11, T34);
    SET(c, d, a, b, 11, 16, T35);
    SET(b, c, d, a, 14, 23, T36);
    SET(a, b, c, d,  1,  4, T37);
    SET(d, a, b, c,  4, 11, T38);
    SET(c, d, a, b,  7, 16, T39);
    SET(b, c, d, a, 10, 23, T40);
    SET(a, b, c, d, 13,  4, T41);
    SET(d, a, b, c,  0, 11, T42);
    SET(c, d, a, b,  3, 16, T43);
    SET(b, c, d, a,  6, 23, T44);
    SET(a, b, c, d,  9,  4, T45);
    SET(d, a, b, c, 12, 11, T46);
    SET(c, d, a, b, 15, 16, T47);
    SET(b, c, d, a,  2, 23, T48);
#undef SET

     /* Round 4. */
     /* Let [abcd k s t] denote the operation
          a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s). */
#define I(x, y, z) ((y) ^ ((x) | ~(z)))
#define SET(a, b, c, d, k, s, Ti)\
  t = a + I(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
     /* Do the following 16 operations. */
    SET(a, b, c, d,  0,  6, T49);
    SET(d, a, b, c,  7, 10, T50);
    SET(c, d, a, b, 14, 15, T51);
    SET(b, c, d, a,  5, 21, T52);
    SET(a, b, c, d, 12,  6, T53);
    SET(d, a, b, c,  3, 10, T54);
    SET(c, d, a, b, 10, 15, T55);
    SET(b, c, d, a,  1, 21, T56);
    SET(a, b, c, d,  8,  6, T57);
    SET(d, a, b, c, 15, 10, T58);
    SET(c, d, a, b,  6, 15, T59);
    SET(b, c, d, a, 13, 21, T60);
    SET(a, b, c, d,  4,  6, T61);
    SET(d, a, b, c, 11, 10, T62);
    SET(c, d, a, b,  2, 15, T63);
    SET(b, c, d, a,  9, 21, T64);
#undef SET

     /* Then perform the following additions. (That is increment each
        of the four registers by the value it had before this block
        was started.) */
    pms->abcd[0] += a;
    pms->abcd[1] += b;
    pms->abcd[2] += c;
    pms->abcd[3] += d;
}

void
md5_init(md5_state_t *pms)
{
    pms->count[0] = pms->count[1] = 0;
    pms->abcd[0] = 0x67452301;
    pms->abcd[1] = /*0xefcdab89*/ T_MASK ^ 0x10325476;
    pms->abcd[2] = /*0x98badcfe*/ T_MASK ^ 0x67452301;
    pms->abcd[3] = 0x10325476;
}

void
md5_append(md5_state_t *pms, const md5_byte_t *data, int nbytes)
{
    const md5_byte_t *p = data;
    int left = nbytes;
    int offset = (pms->count[0] >> 3) & 63;
    md5_word_t nbits = (md5_word_t)(nbytes << 3);

    if (nbytes <= 0)
	return;

    /* Update the message length. */
    pms->count[1] += nbytes >> 29;
    pms->count[0] += nbits;
    if (pms->count[0] < nbits)
	pms->count[1]++;

    /* Process an initial partial block. */
    if (offset) {
	int copy = (offset + nbytes > 64 ? 64 - offset : nbytes);

	memcpy(pms->buf + offset, p, copy);
	if (offset + copy < 64)
	    return;
	p += copy;
	left -= copy;
	md5_process(pms, pms->buf);
    }

    /* Process full blocks. */
    for (; left >= 64; p += 64, left -= 64)
	md5_process(pms, p);

    /* Process a final partial block. */
    if (left)
	memcpy(pms->buf, p, left);
}

void
md5_finish(md5_state_t *pms, md5_byte_t digest[16])
{
    static const md5_byte_t pad[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    md5_byte_t data[8];
    int i;

    /* Save the length before padding. */
    for (i = 0; i < 8; ++i)
	data[i] = (md5_byte_t)(pms->count[i >> 2] >> ((i & 3) << 3));
    /* Pad to 56 bytes mod 64. */
    md5_append(pms, pad, ((55 - (pms->count[0] >> 3)) & 63) + 1);
    /* Append the length. */
    md5_append(pms, data, 8);
    for (i = 0; i < 16; ++i)
	digest[i] = (md5_byte_t)(pms->abcd[i >> 2] >> ((i & 3) << 3));
}

/* Initialize structure containing state of computation.
(RFC 1321, 3.3: Step 3)  */
void
md5_init_ctx(struct md5_ctx *ctx)
{
    ctx->A = (md5_uint32)0x67452301;
    ctx->B = (md5_uint32)0xefcdab89;
    ctx->C = (md5_uint32)0x98badcfe;
    ctx->D = (md5_uint32)0x10325476;

    ctx->total[0] = ctx->total[1] = 0;
    ctx->buflen = 0;
}

#ifndef WORDS_BIGENDIAN
# define SWAP(n) (n)
#else
# define SWAP(n)							\
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
#endif


/* These are the four functions used in the four steps of the MD5 algorithm
and defined in the RFC 1321.  The first function is a little bit optimized
(as found in Colin Plumbs public domain implementation).  */
/* #define FF(b, c, d) ((b & c) | (~b & d)) */
#define FF(b, c, d) (d ^ (b & (c ^ d)))
#define FG(b, c, d) FF (d, b, c)
#define FH(b, c, d) (b ^ c ^ d)
#define FI(b, c, d) (c ^ (b | ~d))

static void
md5_process_block(const void *buffer, size_t len, struct md5_ctx *ctx)
{
    md5_uint32 correct_words[16];
    const md5_uint32 *words = (const md5_uint32 *)buffer;
    size_t nwords = len / sizeof(md5_uint32);
    const md5_uint32 *endp = words + nwords;
    md5_uint32 A = ctx->A;
    md5_uint32 B = ctx->B;
    md5_uint32 C = ctx->C;
    md5_uint32 D = ctx->D;

    /* First increment the byte count.  RFC 1321 specifies the possible
    length of the file up to 2^64 bits.  Here we only compute the
    number of bytes.  Do a double word increment.  */
    ctx->total[0] += len;
    if (ctx->total[0] < len)
        ++ctx->total[1];

    /* Process all bytes in the buffer with 64 bytes in each round of
    the loop.  */
    while (words < endp)
    {
        md5_uint32 *cwp = correct_words;
        md5_uint32 A_save = A;
        md5_uint32 B_save = B;
        md5_uint32 C_save = C;
        md5_uint32 D_save = D;

        /* First round: using the given function, the context and a constant
        the next context is computed.  Because the algorithms processing
        unit is a 32-bit word and it is determined to work on words in
        little endian byte order we perhaps have to change the byte order
        before the computation.  To reduce the work for the next steps
        we store the swapped words in the array CORRECT_WORDS.  */

#define OP(a, b, c, d, s, T)						\
      do								\
        {								\
	  a += FF (b, c, d) + (*cwp++ = SWAP (*words)) + T;		\
	  ++words;							\
	  CYCLIC (a, s);						\
	  a += b;							\
        }								\
      while (0)

        /* It is unfortunate that C does not provide an operator for
        cyclic rotation.  Hope the C compiler is smart enough.  */
#define CYCLIC(w, s) (w = (w << s) | (w >> (32 - s)))

        /* Before we start, one word to the strange constants.
        They are defined in RFC 1321 as

        T[i] = (int) (4294967296.0 * fabs (sin (i))), i=1..64
        */

        /* Round 1.  */
        OP(A, B, C, D, 7, (md5_uint32)0xd76aa478);
        OP(D, A, B, C, 12, (md5_uint32)0xe8c7b756);
        OP(C, D, A, B, 17, (md5_uint32)0x242070db);
        OP(B, C, D, A, 22, (md5_uint32)0xc1bdceee);
        OP(A, B, C, D, 7, (md5_uint32)0xf57c0faf);
        OP(D, A, B, C, 12, (md5_uint32)0x4787c62a);
        OP(C, D, A, B, 17, (md5_uint32)0xa8304613);
        OP(B, C, D, A, 22, (md5_uint32)0xfd469501);
        OP(A, B, C, D, 7, (md5_uint32)0x698098d8);
        OP(D, A, B, C, 12, (md5_uint32)0x8b44f7af);
        OP(C, D, A, B, 17, (md5_uint32)0xffff5bb1);
        OP(B, C, D, A, 22, (md5_uint32)0x895cd7be);
        OP(A, B, C, D, 7, (md5_uint32)0x6b901122);
        OP(D, A, B, C, 12, (md5_uint32)0xfd987193);
        OP(C, D, A, B, 17, (md5_uint32)0xa679438e);
        OP(B, C, D, A, 22, (md5_uint32)0x49b40821);

        /* For the second to fourth round we have the possibly swapped words
        in CORRECT_WORDS.  Redefine the macro to take an additional first
        argument specifying the function to use.  */
#undef OP
#define OP(a, b, c, d, k, s, T)						\
      do 								\
	{								\
	  a += FX (b, c, d) + correct_words[k] + T;			\
	  CYCLIC (a, s);						\
	  a += b;							\
	}								\
      while (0)

#define FX(b, c, d) FG (b, c, d)

        /* Round 2.  */
        OP(A, B, C, D, 1, 5, (md5_uint32)0xf61e2562);
        OP(D, A, B, C, 6, 9, (md5_uint32)0xc040b340);
        OP(C, D, A, B, 11, 14, (md5_uint32)0x265e5a51);
        OP(B, C, D, A, 0, 20, (md5_uint32)0xe9b6c7aa);
        OP(A, B, C, D, 5, 5, (md5_uint32)0xd62f105d);
        OP(D, A, B, C, 10, 9, (md5_uint32)0x02441453);
        OP(C, D, A, B, 15, 14, (md5_uint32)0xd8a1e681);
        OP(B, C, D, A, 4, 20, (md5_uint32)0xe7d3fbc8);
        OP(A, B, C, D, 9, 5, (md5_uint32)0x21e1cde6);
        OP(D, A, B, C, 14, 9, (md5_uint32)0xc33707d6);
        OP(C, D, A, B, 3, 14, (md5_uint32)0xf4d50d87);
        OP(B, C, D, A, 8, 20, (md5_uint32)0x455a14ed);
        OP(A, B, C, D, 13, 5, (md5_uint32)0xa9e3e905);
        OP(D, A, B, C, 2, 9, (md5_uint32)0xfcefa3f8);
        OP(C, D, A, B, 7, 14, (md5_uint32)0x676f02d9);
        OP(B, C, D, A, 12, 20, (md5_uint32)0x8d2a4c8a);

#undef FX
#define FX(b, c, d) FH (b, c, d)

        /* Round 3.  */
        OP(A, B, C, D, 5, 4, (md5_uint32)0xfffa3942);
        OP(D, A, B, C, 8, 11, (md5_uint32)0x8771f681);
        OP(C, D, A, B, 11, 16, (md5_uint32)0x6d9d6122);
        OP(B, C, D, A, 14, 23, (md5_uint32)0xfde5380c);
        OP(A, B, C, D, 1, 4, (md5_uint32)0xa4beea44);
        OP(D, A, B, C, 4, 11, (md5_uint32)0x4bdecfa9);
        OP(C, D, A, B, 7, 16, (md5_uint32)0xf6bb4b60);
        OP(B, C, D, A, 10, 23, (md5_uint32)0xbebfbc70);
        OP(A, B, C, D, 13, 4, (md5_uint32)0x289b7ec6);
        OP(D, A, B, C, 0, 11, (md5_uint32)0xeaa127fa);
        OP(C, D, A, B, 3, 16, (md5_uint32)0xd4ef3085);
        OP(B, C, D, A, 6, 23, (md5_uint32)0x04881d05);
        OP(A, B, C, D, 9, 4, (md5_uint32)0xd9d4d039);
        OP(D, A, B, C, 12, 11, (md5_uint32)0xe6db99e5);
        OP(C, D, A, B, 15, 16, (md5_uint32)0x1fa27cf8);
        OP(B, C, D, A, 2, 23, (md5_uint32)0xc4ac5665);

#undef FX
#define FX(b, c, d) FI (b, c, d)

        /* Round 4.  */
        OP(A, B, C, D, 0, 6, (md5_uint32)0xf4292244);
        OP(D, A, B, C, 7, 10, (md5_uint32)0x432aff97);
        OP(C, D, A, B, 14, 15, (md5_uint32)0xab9423a7);
        OP(B, C, D, A, 5, 21, (md5_uint32)0xfc93a039);
        OP(A, B, C, D, 12, 6, (md5_uint32)0x655b59c3);
        OP(D, A, B, C, 3, 10, (md5_uint32)0x8f0ccc92);
        OP(C, D, A, B, 10, 15, (md5_uint32)0xffeff47d);
        OP(B, C, D, A, 1, 21, (md5_uint32)0x85845dd1);
        OP(A, B, C, D, 8, 6, (md5_uint32)0x6fa87e4f);
        OP(D, A, B, C, 15, 10, (md5_uint32)0xfe2ce6e0);
        OP(C, D, A, B, 6, 15, (md5_uint32)0xa3014314);
        OP(B, C, D, A, 13, 21, (md5_uint32)0x4e0811a1);
        OP(A, B, C, D, 4, 6, (md5_uint32)0xf7537e82);
        OP(D, A, B, C, 11, 10, (md5_uint32)0xbd3af235);
        OP(C, D, A, B, 2, 15, (md5_uint32)0x2ad7d2bb);
        OP(B, C, D, A, 9, 21, (md5_uint32)0xeb86d391);

        /* Add the starting values of the context.  */
        A += A_save;
        B += B_save;
        C += C_save;
        D += D_save;
    }

    /* Put checksum in context given as argument.  */
    ctx->A = A;
    ctx->B = B;
    ctx->C = C;
    ctx->D = D;
}

/* This array contains the bytes used to pad the buffer to the next
64-byte boundary.  (RFC 1321, 3.1: Step 1)  */
static const unsigned char fillbuf[64] = { 0x80, 0 /* , 0, 0, ...  */ };

/* Put result from CTX in first 16 bytes following RESBUF.  The result
must be in little endian byte order.

IMPORTANT: On some systems it is required that RESBUF is correctly
aligned for a 32 bits value.  */
static void *
md5_read_ctx(const struct md5_ctx *ctx, void *resbuf)
{
    ((md5_uint32 *)resbuf)[0] = SWAP(ctx->A);
    ((md5_uint32 *)resbuf)[1] = SWAP(ctx->B);
    ((md5_uint32 *)resbuf)[2] = SWAP(ctx->C);
    ((md5_uint32 *)resbuf)[3] = SWAP(ctx->D);

    return resbuf;
}

/* Process the remaining bytes in the internal buffer and the usual
prolog according to the standard and write the result to RESBUF.

IMPORTANT: On some systems it is required that RESBUF is correctly
aligned for a 32 bits value.  */
void *
md5_finish_ctx(struct md5_ctx *ctx, void *resbuf)
{
    /* Take yet unprocessed bytes into account.  */
    md5_uint32 bytes = ctx->buflen;
    size_t pad;

    /* Now count remaining bytes.  */
    ctx->total[0] += bytes;
    if (ctx->total[0] < bytes)
        ++ctx->total[1];

    pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
    memcpy(&ctx->buffer[bytes], fillbuf, pad);

    /* Put the 64-bit file length in *bits* at the end of the buffer.  */
    *(md5_uint32 *)&ctx->buffer[bytes + pad] = SWAP(ctx->total[0] << 3);
    *(md5_uint32 *)&ctx->buffer[bytes + pad + 4] = SWAP((ctx->total[1] << 3) |
        (ctx->total[0] >> 29));

    /* Process last bytes.  */
    md5_process_block(ctx->buffer, bytes + pad + 8, ctx);

    return md5_read_ctx(ctx, resbuf);
}

void
md5_process_bytes(const void *buffer, size_t len, struct md5_ctx *ctx)
{
    /* When we already have some bits in our internal buffer concatenate
    both inputs first.  */
    if (ctx->buflen != 0)
    {
        size_t left_over = ctx->buflen;
        size_t add = 128 - left_over > len ? len : 128 - left_over;

        memcpy(&ctx->buffer[left_over], buffer, add);
        ctx->buflen += add;

        if (left_over + add > 64)
        {
            md5_process_block(ctx->buffer, (left_over + add) & ~63, ctx);
            /* The regions in the following copy operation cannot overlap.  */
            memcpy(ctx->buffer, &ctx->buffer[(left_over + add) & ~63],
                (left_over + add) & 63);
            ctx->buflen = (left_over + add) & 63;
        }

        buffer = (const void *)((const char *)buffer + add);
        len -= add;
    }

    /* Process available complete blocks.  */
    if (len > 64)
    {
        md5_process_block(buffer, len & ~63, ctx);
        buffer = (const void *)((const char *)buffer + (len & ~63));
        len &= 63;
    }

    /* Move remaining bytes in internal buffer.  */
    if (len > 0)
    {
        memcpy(ctx->buffer, buffer, len);
        ctx->buflen = len;
    }
}

