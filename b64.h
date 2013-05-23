#ifndef _B64_H
#define _B64_H

int b64_encode(const char *in, int in_len, char *out, int out_size);

int b64_decode(const char *in, char *out, int out_size);

#endif
