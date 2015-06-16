#ifndef UTIL_H_
#define UTIL_H_

#include "prng.h"

#define max(a,b) \
	({ __typeof__ (a) _a = (a); \
	 __typeof__ (b) _b = (b); \
		     _a > _b ? _a : _b; })

#define min(a,b) \
	({ __typeof__ (a) _a = (a); \
	 __typeof__ (b) _b = (b); \
		     _a < _b ? _a : _b; })

int to_base64(const unsigned char *data, size_t len,
		char *out, size_t *outlen);

int from_base64(const char *base64, size_t len,
		unsigned char *out, size_t *outlen);

void fill_random(unsigned char *data, size_t len);

void xor_arr(u8 *dst, const u8 *src, size_t len);


#endif
