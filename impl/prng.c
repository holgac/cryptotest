#include <string.h>
#include "prng.h"
#include "util.h"

/**
 * mt19937_init - initializes mt instance
 * @mt: mt instance (should be allocated externally)
 * @seed: initial seed
 */
void mt19937_init(struct mt19937 *mt, u32 seed)
{
	size_t i;
	mt->idx = 0;
	mt->state[0] = seed;
	for(i=1; i<624; ++i)
		mt->state[i] = i + 0x6c078965 * (mt->state[i-1] ^ (mt->state[i-1]>>30));
}

/**
 * mt19937_gen: Generates a 32 bit unsigned value
 * @mt: mt instance
 *
 * range is [0, 0xfffffffd]
 * vulnerable to timing attacks!
 */
u32 mt19937_gen(struct mt19937 *mt)
{
	size_t i;
	u32 y;
	if(mt->idx == 0) {
		for(i=0; i<624; ++i) {
			y = (mt->state[i] & 0x80000000) + (mt->state[(i+1)%624] & 0x7fffffff);
			mt->state[i] = mt->state[(i+397)%624] ^ (y>>1) ^ (y&1)*0x9908b0df;
		}
	}
	y = mt->state[mt->idx];
	y ^= (y<<7) & 0x9d2c5680;
	y ^= (y<<15) & 0xefc60000;
	y ^= y >> 18;
	mt->idx = (mt->idx+1) % 624;
	return y;
}

static void mt19937c_genall(struct mt19937_cached *mt)
{
	size_t i;
	u32 y;
	for(i=0; i<624; ++i) {
		y = (mt->mt.state[i] & 0x80000000) + (mt->mt.state[(i+1)%624] & 0x7fffffff);
		mt->mt.state[i] = mt->mt.state[(i+397)%624] ^ (y>>1) ^ (y&1)*0x9908b0df;
		y = mt->mt.state[i];
		y ^= (y<<7) & 0x9d2c5680;
		y ^= (y<<15) & 0xefc60000;
		y ^= y >> 18;
		mt->vals_u32[i] = y;
	}
	mt->mt.idx = 0;	
}

/**
 * mt19937c_init - initializes cached mt instance
 * @mt: mt instance (should be allocated externally)
 * @seed: initial seed
 */
void mt19937c_init(struct mt19937_cached *mt, u32 seed)
{
	mt19937_init(&mt->mt, seed);
	mt19937c_genall(mt);
}

/**
 * mt19937c_fill - fills the given memory segment with random data
 * @mt: MT instance
 * @ptr: pointer to the memory segment
 * @len: length of data in bytes
 *
 * This function has no alignment restrictions at all.
 */
void mt19937c_fill(struct mt19937_cached *mt, void *ptr, size_t len)
{
	size_t avlen;
	u8 *p = ptr;
	while(len) {
		avlen = 624*4 - mt->mt.idx;
		if(len >= avlen) {
			len -= avlen;
			memcpy(p, mt->vals + mt->mt.idx, avlen);
			mt19937c_genall(mt);
			p += avlen;
		} else {
			memcpy(p, mt->vals + mt->mt.idx, len);
			mt->mt.idx += len;
			len = 0;
		}
	}
}

void mt19937c_xor(struct mt19937_cached *mt, u8 *ptr, size_t len)
{
	size_t avlen;
	u8 *p = ptr;
	while(len) {
		avlen = 624*4 - mt->mt.idx;
		if(len >= avlen) {
			len -= avlen;
			xor_arr(p, mt->vals + mt->mt.idx, avlen);
			mt19937c_genall(mt);
			p += avlen;
		} else {
			xor_arr(p, mt->vals + mt->mt.idx, len);
			mt->mt.idx += len;
			len = 0;
		}
	}
}

