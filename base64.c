#include "base64.h"

static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void encodeblock(const unsigned char *in, char *out, size_t len)
{
    out[0] = (char) cb64[ (int)(in[0] >> 2) ];
    out[1] = (char) cb64[ (int)(((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)) ];
    out[2] = (char) (len > 1 ? cb64[ (int)(((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)) ] : '=');
    out[3] = (char) (len > 2 ? cb64[ (int)(in[2] & 0x3f) ] : '=');
}

char * base64_encode(const unsigned char * in, size_t inlen, char * out, size_t outlen)
{
    size_t i;
    char * o = out;
    for (i=0;i<=inlen;i+=3) {
        if (o+4>out+outlen) return 0;
        encodeblock(in+i, o, (inlen>i+3) ? 3 : (inlen-i));
        o += 4;
    }
    *o = 0;
    return out;
}

unsigned char * base64_decode(const char * input, size_t inlen, unsigned char * output, size_t outlen)
{
    return output;
}

char base64_encode_value(int value_in)
{
    if (value_in > 63) return '=';
    return cb64[value_in];
}

int base64_decode_value(char value_in)
{
    if (value_in>='A' && value_in<='Z') return value_in-'A';
    if (value_in>='a' && value_in<='z') return value_in-'a'+26;
    if (value_in>='0' && value_in<='9') return value_in-'0'+52;
    if (value_in=='+') return 62;
    if (value_in=='/') return 63;
    return -1;
}
