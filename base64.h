#ifndef CRYPTO_BASE64_H
#define CRYPTO_BASE64_H

#include <stddef.h>

char * base64_encode(const unsigned char * input, size_t inlen, char * output, size_t outlen);
unsigned char * base64_decode(const char * input, size_t inlen, unsigned char * output, size_t outlen);

char base64_encode_value(int value_in);
int base64_decode_value(char value_in);

#endif
