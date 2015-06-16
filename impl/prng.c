#include "prng.h"

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
			mt->state[i] = mt->state[(i+397)%624] ^ (y>>1) ^ (y%2)*0x9908b0df;
		}
	}
	y = mt->state[mt->idx];
	y ^= (y<<7) & 0x9d2c5680;
	y ^= (y<<15) & 0xefc60000;
	y ^= y >> 18;
	mt->idx = (mt->idx+1) % 624;
	return y;
}

/**
 * mt19937_fill - fills the given data with random bytes
 * @mt: mt instance
 * @ptr: data to be filled
 * @len: length of data in bytes
 *
 * given data should be properly aligned to store unsigned int,
 * len also should be a multiple of 4.
 */
void mt19937_fill(struct mt19937 *mt, void *ptr, size_t len)
{
	u32 *p = ptr;
	size_t i, plen = len/4;
	for(i=0; i<plen; i++) {
		p[i] = mt19937_gen(mt);
	}
}

