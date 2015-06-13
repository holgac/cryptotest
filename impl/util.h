#ifndef UTIL_H_
#define UTIL_H_


int to_base64(const unsigned char *data, size_t len,
		char *out, size_t *outlen);
int from_base64(const char *base64, size_t len,
		unsigned char *out, size_t *outlen);
#endif
