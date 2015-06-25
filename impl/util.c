#include <stddef.h>
#include <stdlib.h>
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

static int pfrom_base64(char c1, char c2, char c3, char c4, unsigned char *data)
{
	unsigned char v1, v2, v3, v4;
	if(c1 < 0 || c2 < 0 || c3 < 0 || c4 < 0)
		return -EINVAL;
	v1 = base64_rmap[(int)c1];
	v2 = base64_rmap[(int)c2];
	v3 = base64_rmap[(int)c3];
	v4 = base64_rmap[(int)c4];
	/* if any of them is 64, it has 64 bit set */
	if((v1|v2|v3|v4) & 64)
		return -EINVAL;
	data[0] = (v1 << 2) | (v2 >> 4);
	data[1] = (v2 << 4) | (v3 >> 2);
	data[2] = (v3 << 6) | v4;
	return 0;
}

/**
 * from_base64 - converts the given base64 data to raw hex format
 * @base64: base64-encoded data to be converted to
 * @len: data length
 * @out: memory to hex base64 representation of data, NOT null terminated.
 * @outlen: out length, may be null.
 *
 * @out should have enough memory to store ceil(len*3/4) of data.
 * This method can perform inline conversion.
 */
int from_base64(const char *base64, size_t len,
		unsigned char *out, size_t *outlen)
{
	size_t i, olen=0, blen = len-4;
	int r;
	if(len%4)
		return -EINVAL;
	for(i=0; i<blen; i+=4) {
		r = pfrom_base64(base64[i], base64[i+1], base64[i+2], base64[i+3],
				out + olen);
		if(r)
			return r;
		olen +=3;
	}
	if(base64[i+2] == '=') {
		r = pfrom_base64(base64[i], base64[i+1], 'A', 'A',
				out + olen);
		if(r)
			return r;
		olen +=1;
	} else if(base64[i+3] == '=') {
		r = pfrom_base64(base64[i], base64[i+1], base64[i+2], 'A',
				out + olen);
		if(r)
			return r;
		olen +=2;
	} else {
		r = pfrom_base64(base64[i], base64[i+1], base64[i+2], base64[i+3],
				out + olen);
		if(r)
			return r;
		olen +=3;
	}
	if(outlen)
		*outlen = olen;
	return 0;
}

/**
 * fill_random - fills the data with random values
 * @data: data to be filled
 * @len: length of data
 *
 * Randomization is currently with rand()
 * TODO: use MT19937
 */
void fill_random(unsigned char *data, size_t len)
{
	size_t i;
	for(i=0; i<len; ++i)
		data[i] = rand()%256;
}

/**
 * xor_arr - xors given memory segments
 * @dst: xor destination (to be xorred with @src)
 * @src: xor source (unmodified)
 * @len: length of memory segments
 */
void xor_arr(u8 *dst, const u8 *src, size_t len)
{
	size_t i;
	for(i=0; i<len; ++i)
		dst[i] ^= src[i];
}











