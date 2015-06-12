#ifndef RYPTO_H_
#define RYPTO_H_

#include <stddef.h>

void init();
void cleanup();


#define FREQMAP_SPACE 26
#define FREQMAP_LEN 27
/*
 * 0-25 for A to Z,
 * 26 for space (0.2 selected)
 */
extern double freqmap_en[FREQMAP_LEN];

#define ALPHABET_EN_LEN 26
#define ALPHABET_EN_PRIME_LEN 12
extern unsigned char alphabet_en[ALPHABET_EN_LEN];
extern int alphabet_en_primes[ALPHABET_EN_PRIME_LEN];

extern double bigram_en[ALPHABET_EN_LEN][ALPHABET_EN_LEN];
void load_bigrams();

extern unsigned char base64_rmap[128];

int cipher_shift(unsigned char *data, size_t datalen, unsigned char *shiftdata,
		size_t shiftlen, unsigned char *alphabet, size_t alphabetlen, unsigned char *out);
void freqmap_calc(unsigned char *data, size_t datalen, double *out);
void freqmap_pcalc_xor(unsigned char *data, size_t datalen, unsigned char k, size_t interval, double *out);
double freqmap_comp(double *f1, double *f2);
int cipher_affine(unsigned char *data, size_t datalen,
		int a, int b, unsigned char *alphabet, size_t alphabetlen, unsigned char *out);
int cipher_substitution(unsigned char *data, size_t datalen, unsigned char *sortedalphabet,
		unsigned char *alphabet, size_t alphabetlen, unsigned char *out);
void cipher_xor(unsigned char *data, size_t datalen, unsigned char *key, size_t keylen,
		unsigned char *out);

double bigram_fitness(unsigned char *data, size_t datalen);

void xor_arr(unsigned char *dst, const unsigned char *src, size_t len);
size_t pad_pkcs7(unsigned char *data, size_t datalen, size_t blocklen);
ssize_t unpad_pkcs7(unsigned char *data, size_t datalen, size_t blocklen);

/*
 * horizontally rearranges memory so that
 * out[0] = data[0]
 * out[1] = data[vertsize]
 * ...
 * out[datalen/vertsize] = data[1]
 */
void hor_arrange(const unsigned char *data, size_t datalen, size_t vertsize, unsigned char *out);
/*
 * Calculates kasiski stats for given data.
 * returns normalized data.
 */
void kasiski_calc(const unsigned char *data, size_t datalen, double *out, size_t outlen);

/*
 * converts hex string of len len to
 * data of len len/2.
 * data should have enough memory in advance.
 */
void from_hex(const char *hex, size_t len, unsigned char *data);
/*
 * converts data of len len to
 * hex string of len len*2.
 * data should have enough memory in advance
 */
void to_hex(const unsigned char *data, size_t len, char *hex);
/*
 * convert base64 of len len
 * to data of ceil(len * 3/4)
 * data should have enough memory in advance.
 */
void from_base64(const char *base64, size_t len, unsigned char *data);

/*
 * for ax + by = gcd(a,b)
 * returns [gcd(a,b), x, y]
 * if a,b are relatively prime,
 * x = a^-1 modulo b
 */
void extended_euclid(long a, long b, long *out);

size_t edit_dist(unsigned char *d1, unsigned char *d2, size_t len);

void fill_random(unsigned char *data, size_t len);

#define CMDLEN 16

struct command {
	char cmd[CMDLEN];
	struct command *next;
	struct command *child;
	unsigned int argcnt;
	void (*perform)(int argc, char **argv);
};

struct command *construct_shift_cmd();
struct command *construct_affine_cmd();
struct command *construct_substitution_cmd();
struct command *construct_matasano_cmd();
struct command *construct_xor_cmd();
struct command *construct_aes_cmd();

#endif
