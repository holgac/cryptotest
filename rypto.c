#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <sys/stat.h>
#include "rypto.h"

double freqmap_en[FREQMAP_LEN] = {0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020,
	0.061, 0.070, 0.002, 0.008, 0.040, 0.024, 0.067, 0.075, 0.019, 0.001,
	0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.001, 0.020, 0.001, 0.200};

unsigned char alphabet_en[ALPHABET_EN_LEN] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
	'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
	'X', 'Y', 'Z'};

int alphabet_en_primes[ALPHABET_EN_PRIME_LEN] = {1,3,5,7,9,11,15,17,19,21,23,25};
double bigram_en[ALPHABET_EN_LEN][ALPHABET_EN_LEN];

void init()
{
	srand(time(NULL));
	if(sizeof(u64) != 8 || sizeof(u32) != 4 || sizeof(u16) != 2 || sizeof(u8) != 1
		|| sizeof(s64) != 8 || sizeof(s32) != 4 || sizeof(s16) != 2
		|| sizeof(s8) != 1) {
		printf("Typedefs are not properly implemented for this system!\n");
	}
}
void cleanup()
{
}

void load_bigrams()
{
	unsigned long bigram_enl[ALPHABET_EN_LEN][ALPHABET_EN_LEN];
	unsigned long long bigram_en_tot = 0;
	FILE* f;
	size_t i, j;
	f = fopen("data/2", "r");
	while(!feof(f))
	{
		char bigram[2];
		unsigned long freq;
		int rd;
		rd = fscanf(f, "%c%c %lu ", bigram, bigram+1, &freq);
		if(rd == 0)
			break;
		bigram_enl[bigram[0]-'A'][bigram[1]-'A'] = freq;
		bigram_en_tot += freq;
	}
	for(i=0; i<ALPHABET_EN_LEN; ++i)
		for(j=0; j<ALPHABET_EN_LEN; ++j)
			bigram_en[i][j] = log10(bigram_enl[i][j] * 1.0 / bigram_en_tot);

}
static ssize_t find_in_data(unsigned char *alphabet, size_t len, unsigned char c)
{
	ssize_t i;
	for(i=0; i<len; ++i)
		if(alphabet[i] == c)
			return i;
	return -1;
}

int get_freqmap_idx(unsigned char c)
{
	if(c >= 'A' && c <= 'Z')
		return c-'A';
	if(c >= 'a' && c <= 'z')
		return c-'a';
	if(c == ' ')
		return FREQMAP_SPACE;
	return -1;
}

double bigram_fitness(unsigned char *data, size_t datalen)
{
	double cur_fitness = 0;
	size_t i;
	for(i=0; i<datalen-1; ++i) {
		int i1, i2;
		i1 = get_freqmap_idx(data[i]);
		i2 = get_freqmap_idx(data[i+1]);
		if(i1 < 0 || i2 < 0) {
			printf("Unexpected letter in bigram_fitness\n");
			return -100000000.0;
		}
		cur_fitness += bigram_en[i1][i2];
	}
	return cur_fitness;
}

void freqmap_pcalc_xor(unsigned char *data, size_t datalen, unsigned char k, size_t interval, double *out)
{
	size_t i;
	double fact = interval * 1.0 / datalen;
	for(i=0; i<FREQMAP_LEN; ++i)
		out[i] = 0.0;
	for(i=0; i<datalen; i += interval) {
		unsigned char v;
		char idx;
		v = data[i] ^ k;
		idx = get_freqmap_idx(v);
		if(idx != -1)
			out[(size_t)idx] += 1;
	}
	for(i=0; i<FREQMAP_LEN; ++i)
		out[i] *= fact;
}

void freqmap_calc(unsigned char *data, size_t datalen, double *out)
{
	size_t i;
	double invdatalen = 1.0 / datalen;
	for(i=0; i<FREQMAP_LEN; ++i)
		out[i] = 0.0;
	for(i=0; i<datalen; ++i) {
		char idx = get_freqmap_idx(data[i]);
		if(idx != -1)
			out[(size_t)idx] += 1;
	}
	for(i=0; i<FREQMAP_LEN; ++i)
		out[i] *= invdatalen;

}

double freqmap_comp(double *f1, double *f2)
{
	double score = 0;
	size_t i;
	for(i=0; i<FREQMAP_LEN; ++i)
		score += f1[i] * f2[i];
	return score;
}

void extended_euclid(long a, long b, long *out)
{
	long s=0, old_s = 1, t = 1, old_t = 0, r = b, old_r = a;
	long quot, tmp;
	while(r != 0) {
		quot = old_r / r;
		tmp = r;
		r = old_r - quot*r;
		old_r = tmp;
		tmp = s;
		s = old_s - quot*s;
		old_s = tmp;
		tmp = t;
		t = old_t - quot*t;
		old_t = tmp;
	}
	out[0] = old_r;
	out[1] = old_s;
	out[2] = old_t;
}
int cipher_shift(unsigned char *data, size_t datalen, unsigned char *shiftdata,
		size_t shiftlen, unsigned char *alphabet, size_t alphabetlen, unsigned char *out)
{
	size_t i;
	for(i=0; i<datalen; ++i) {
		ssize_t idx = find_in_data(alphabet, alphabetlen, data[i]);
		unsigned int res = idx + shiftdata[i%shiftlen];
		if(idx == -1) {
			printf("Out of bound data, unable to cipher_shift!\n");
			return 1;
		}
		out[i] = alphabet[res % alphabetlen];
	}
	return 0;
}


int cipher_affine(unsigned char *data, size_t datalen,
		int a, int b, unsigned char *alphabet, size_t alphabetlen, unsigned char *out)
{
	size_t i;
	for(i=0; i<datalen; ++i) {
		ssize_t idx = find_in_data(alphabet, alphabetlen, data[i]);
		unsigned int res = idx*a + b;
		if(idx == -1) {
			printf("Out of bound data, unable to cipher_affine!\n");
			return 1;
		}
		out[i] = alphabet[res % alphabetlen];
	}
	return 0;
}

int cipher_substitution(unsigned char *data, size_t datalen, unsigned char *sortedalphabet,
		unsigned char *alphabet, size_t alphabetlen, unsigned char *out)
{
	size_t i;
	for(i=0; i<datalen; ++i) {
		ssize_t idx = find_in_data(alphabet, alphabetlen, data[i]);
		if(idx == -1) {
			printf("Out of bound data, unable to cipher_substi!\n");
			return 1;
		}
		out[i] = sortedalphabet[idx];
	}
	return 0;
}

static ssize_t hex_to_dec(char c)
{
	if(c >= '0' && c <= '9')
		return c - '0';
	if(c >= 'A' && c <= 'F')
		return c + 10 - 'A';
	if(c >= 'a' && c <= 'f')
		return c + 10 - 'a';
	return -1;
}
void from_hex(const char *hex, size_t len, unsigned char *data)
{
	size_t i;
	for(i=0; i<len; i += 2)
		data[i/2] = (hex_to_dec(hex[i])<<4) | (hex_to_dec(hex[i+1]));
}
void pto_hex(unsigned char data, char *hex)
{
	if(data < 10)
		hex[0] = '0' + data;
	else
		hex[0] = 'A' + data - 10;
}
void to_hex(const unsigned char *data, size_t len, char *hex)
{
	size_t i;
	for(i=0;i<len; ++i) {
		pto_hex(data[i] >> 4, hex + 2*i);
		pto_hex(data[i] & 0x0f, hex + 2*i + 1);
	}
	hex[len*2] = 0;
}
static ssize_t find_in_data(unsigned char *alphabet, size_t len, unsigned char c);

void cipher_xor(unsigned char *data, size_t datalen, unsigned char *key, size_t keylen,
		unsigned char *out)
{
	size_t i;
	for(i=0; i<datalen; ++i)
		out[i] = data[i] ^ key[i % keylen];
}

void kasiski_calc(const unsigned char *data, size_t datalen, double *out, size_t outlen)
{
	size_t curidx, match;
	size_t matchlen;
	size_t total_match = 0;
	double tmp;
	for(curidx=0; curidx < outlen; ++curidx)
		out[curidx] = 0.0;
	for(curidx=0; curidx<datalen; ++curidx)
	{
		match = curidx+2;
		while(match < datalen) {
			while(match<datalen && data[curidx] != data[match])
				++match;
			matchlen = 1;
			while((match+matchlen) < datalen && data[curidx+matchlen] == data[match+matchlen])
				matchlen++;
			if(matchlen > 2) {
				size_t deltapos = match - curidx;
				size_t i;
				for(i=1;i<=deltapos;++i) {
					size_t pos_keylen;
					if(deltapos % i)
						continue;
					pos_keylen = deltapos / i;
					if(pos_keylen < outlen) {
						out[pos_keylen] += 1;
						total_match += 1;
					}
				}
			}
			match++;
		}
	}
	if(total_match == 0)
		return;
	tmp = 1.0 / total_match;
	for(curidx=0; curidx < outlen; ++curidx)
		out[curidx] *= tmp;
}
static size_t edit_distance_c(unsigned char c1, unsigned char c2)
{
	size_t i, dist=0;
	unsigned char d = c1^c2;
	for(i=0; i<8; ++i)
		dist += ((d & (1 << i)) != 0);
	return dist;
}

size_t edit_dist(unsigned char *d1, unsigned char *d2, size_t len)
{
	size_t i, dist=0;
	for(i=0; i<len; ++i)
		dist += edit_distance_c(d1[i], d2[i]);
	return dist;
}

void hor_arrange(const unsigned char *data, size_t datalen, size_t vertsize, unsigned char *out)
{
	size_t i, j, lastidx=0;
	for(i=0; i < vertsize; ++i) {
		for(j=0; i+j*vertsize < datalen; ++j) {
			out[lastidx++] = data[i+j*vertsize];
		}
	}
}


















