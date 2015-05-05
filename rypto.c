#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "rypto.h"

double freqmap_en[FREQMAP_LEN] = {0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020,
	0.061, 0.070, 0.002, 0.008, 0.040, 0.024, 0.067, 0.075, 0.019, 0.001,
	0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.001, 0.020, 0.001, 0.200};

unsigned char alphabet_en[ALPHABET_EN_LEN] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
	'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
	'X', 'Y', 'Z'};

static ssize_t find_in_data(unsigned char *alphabet, size_t len, unsigned char c)
{
	ssize_t i;
	for(i=0; i<len; ++i)
		if(alphabet[i] == c)
			return i;
	return -1;
}
static char get_freqmap_idx(unsigned char c)
{
	if(c >= 'A' && c <= 'Z')
		return c-'A';
	if(c >= 'a' && c <= 'z')
		return c-'a';
	if(c == ' ')
		return FREQMAP_SPACE;
	return -1;
}

void freqmap_calc(unsigned char *data, size_t datalen, double *out)
{
	size_t i;
	for(i=0; i<FREQMAP_LEN; ++i)
		out[i] = 0.0;
	for(i=0; i<datalen; ++i) {
		char idx = get_freqmap_idx(data[i]);
		if(idx != -1)
			out[(size_t)idx] += 1;
	}
	for(i=0; i<FREQMAP_LEN; ++i)
		out[i] /= datalen;

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
			printf("Out of bound data, unable to cipher_shift!\n");
			return 1;
		}
		out[i] = alphabet[res % alphabetlen];
	}
	return 0;
}









