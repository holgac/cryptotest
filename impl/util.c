#include <stddef.h>
#include <errno.h>
#include "util.h"
#include "consts.h"

/**
 * to_base64 - converts the given raw data to base64
 * @data: data to be converted to
 * @len: data length
 * @out: memory to write base64 representation of data, null terminated.
 * @outlen: out length, may be null. if not, index of null.
 *
 * @out should have enough memory to store ceil(len*4/3) of data.
 */
int to_base64(const unsigned char *data, size_t len,
		char *out, size_t *outlen)
{
	size_t blen = 3*(len/3);
	size_t i, olen=0;
	if(len%2)
		return -EINVAL;
	for(i=0; i<blen; i+=3) {
		out[olen] = base64_map[data[i]>>2];
		out[olen+1] = base64_map[((data[i] & 0x3)<<4) | (data[i+1] >> 4)];
		out[olen+2] = base64_map[((data[i+1] & 0x0f)<< 2) | (data[i+2] >> 6)];
		out[olen+3] = base64_map[data[i+2] & 0x3f];
		olen += 4;
	}
	if(i == (len-1)) {
		out[olen] = base64_map[data[i]>>2];
		out[olen+1] = base64_map[((data[i] & 0x3)<<4)];
		out[olen+2] = '=';
		out[olen+3] = '=';
		olen += 4;
	} else if(i == (len - 2)) {
		out[olen] = base64_map[data[i]>>2];
		out[olen+1] = base64_map[((data[i] & 0x3)<<4) | (data[i+1] >> 4)];
		out[olen+2] = base64_map[((data[i+1] & 0x0f)<< 2)];
		out[olen+3] = '=';
		olen += 4;
	}
	out[olen] = 0;
	if(outlen)
		*outlen = olen;
	return 0;
}

