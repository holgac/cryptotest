#ifndef PRNG_H_
#define PRNG_H_
#include "../rypto.h"

/**
 * mt19937 - Mersenne Twister
 * @state: MT state
 * @idx: current index
 *
 * do not alter from outside, use mt19937_* functions.
 */
struct mt19937
{
	u32 state[624];
	u32 idx;
};

void mt19937_init(struct mt19937 *mt, u32 seed);
u32 mt19937_gen(struct mt19937 *mt);

/**
 * mt19937_cached - Cached Mersenne Twister
 * @mt: actual MT
 * @vals: values
 * @vals_u32: values in u32 format
 *
 * mt.idx is used as a byte index.
 */
struct mt19937_cached
{
	struct mt19937 mt;
	union {
		u32 vals_u32[624];
		u8 vals[624*4];
	};
};

void mt19937c_init(struct mt19937_cached *mt, u32 seed);
void mt19937c_fill(struct mt19937_cached *mt, void *ptr, size_t len);
void mt19937c_xor(struct mt19937_cached *mt, u8 *ptr, size_t len);


#endif

