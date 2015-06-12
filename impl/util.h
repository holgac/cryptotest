#ifndef UTIL_H_
#define UTIL_H_


int to_base64(const unsigned char *data, size_t len,
		char *base64, size_t *outlen);

#endif
