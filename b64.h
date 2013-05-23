#ifndef _B64_H
#define _B64_H

#include <stdint.h>

int b64_encode(const uint8_t *in, int in_len, char *out, int out_size);

int b64_decode(const char *in, uint8_t *out, int out_size);

#endif
