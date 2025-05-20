#include "commons.h"

#ifndef _b64
#define _b64

#define MAX_B64_DATA sizeof(struct packet) / 3 * 4

int b64_isvalidchar(char c);

int b64_strlen(const char *in);

int b64_decode(const char *in, char *out, int input_len);

int b64_encode(const unsigned char *in, unsigned char *out, unsigned long len);

#endif