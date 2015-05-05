#ifndef RYPTO_H_
#define RYPTO_H_

#define FREQMAP_SPACE 26
#define FREQMAP_LEN 27

/*
 * 0-25 for A to Z,
 * 26 for space (0.2 selected)
 */
extern double freqmap_en[FREQMAP_LEN];

#define ALPHABET_EN_LEN 26
extern unsigned char alphabet_en[ALPHABET_EN_LEN];
int cipher_shift(unsigned char *data, size_t datalen, unsigned char *shiftdata,
		size_t shiftlen, unsigned char *alphabet, size_t alphabetlen, unsigned char *out);
void freqmap_calc(unsigned char *data, size_t datalen, double *out);
double freqmap_comp(double *f1, double *f2);
int cipher_affine(unsigned char *data, size_t datalen,
		int a, int b, unsigned char *alphabet, size_t alphabetlen, unsigned char *out);

/*
 * for ax + by = gcd(a,b)
 * returns [gcd(a,b), x, y]
 * if a,b are relatively prime,
 * x = a^-1 modulo b
 */
void extended_euclid(long a, long b, long *out);

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

#endif
