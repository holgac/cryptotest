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
void mt19937_fill(struct mt19937 *mt, void *ptr, size_t len);

#endif

