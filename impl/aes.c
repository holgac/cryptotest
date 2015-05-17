#include <string.h>
#include <stdlib.h>
#include "aes.h"
#include "consts.h"

static void invshift_row(unsigned char *data)
{
	unsigned char tmp;
	tmp = data[9];
	data[9] = data[5];
	data[5] = data[1];
	data[1] = data[13];
	data[13] = tmp;

	tmp = data[2];
	data[2] = data[10];
	data[10] = tmp;
	tmp = data[6];
	data[6] = data[14];
	data[14] = tmp;

	tmp = data[3];
	data[3] = data[7];
	data[7] = data[11];
	data[11] = data[15];
	data[15] = tmp;
}

static void invmix_column(unsigned char *data)
{
	unsigned char old[16];
	size_t i;
	memcpy(old, data, 16);
	for (i=0; i<16; i+=4) {
		data[i] = mult14[old[i]] ^ mult11[old[i+1]] ^ mult13[old[i+2]] ^ mult9[old[i+3]];
		data[i+1] = mult9[old[i]] ^ mult14[old[i+1]] ^ mult11[old[i+2]] ^ mult13[old[i+3]];
		data[i+2] = mult13[old[i]] ^ mult9[old[i+1]] ^ mult14[old[i+2]] ^ mult11[old[i+3]];
		data[i+3] = mult11[old[i]] ^ mult13[old[i+1]] ^ mult9[old[i+2]] ^ mult14[old[i+3]];
	}
}

static void invsub_byte(unsigned char *data)
{
	size_t i;
	for(i=0; i<16; ++i)
		data[i] = invs_box[data[i]];
}

static inline unsigned char gf_mult2(unsigned char d)
{
	return (d << 1) ^ (0x11b & -(d>>7));
}

static void add_rk(unsigned char *data, unsigned char *rk)
{
	size_t i;
	for(i=0; i<16; ++i)
		data[i] ^= rk[i];
}

static void calc_new_rk(unsigned char *rk, unsigned char *rc, unsigned char *out)
{
	size_t i;
	out[0] = s_box[rk[13]] ^ rk[0] ^ *rc;
	out[1] = s_box[rk[14]] ^ rk[1];
	out[2] = s_box[rk[15]] ^ rk[2];
	out[3] = s_box[rk[12]] ^ rk[3];
	for(i=4; i<16; ++i)
		out[i] = out[i-4] ^ rk[i];
	*rc = gf_mult2(*rc);
}

static void sub_byte(unsigned char *data)
{
	size_t i;
	for(i=0; i<16; ++i)
		data[i] = s_box[data[i]];
}
static void shift_row(unsigned char *data)
{
	unsigned char tmp;
	tmp = data[1];
	data[1] = data[5];
	data[5] = data[9];
	data[9] = data[13];
	data[13] = tmp;
	tmp = data[2];
	data[2] = data[10];
	data[10] = tmp;
	tmp = data[6];
	data[6] = data[14];
	data[14] = tmp;

	tmp = data[11];
	data[11] = data[7];
	data[7] = data[3];
	data[3] = data[15];
	data[15] = tmp;
}
static void mix_column(unsigned char *data)
{
	unsigned char old[16];
	size_t i;
	memcpy(old, data, 16);
	for(i=0; i<16; i+=4) {
		data[i] = gf_mult2(old[i]) ^ gf_mult2(old[i+1]) ^ old[i+1] ^ old[i+2] ^ old[i+3];
		data[i+1] = old[i] ^ gf_mult2(old[i+1]) ^ gf_mult2(old[i+2]) ^ old[i+2] ^ old[i+3];
		data[i+2] = old[i] ^ old[i+1] ^ gf_mult2(old[i+2]) ^ gf_mult2(old[i+3]) ^ old[i+3];
		data[i+3] = gf_mult2(old[i]) ^ old[i] ^ old[i+1] ^ old[i+2] ^ gf_mult2(old[i+3]);
	}
}

void aes_128_ecb_init(struct aes_opmod *opmod, const unsigned char *key,
		const unsigned char *iv)
{
	memcpy(opmod->context, key, 16);
}

static void aes_128_ecb_encrypt(struct aes_opmod *opmod, unsigned char *data)
{
	const size_t nr = 9;
	unsigned char rk[16*(nr+2)], rc=1;
	size_t r=0, i;
	memcpy(rk, opmod->context, 16);
	for(i=0; i<(nr+1); ++i)
		calc_new_rk(rk + i*16, &rc, rk + (i+1)*16);
	add_rk(data, rk);
	for(r=0; r<nr; ++r) {
		sub_byte(data);
		shift_row(data);
		mix_column(data);
		add_rk(data, rk+(r+1)*16);
	}
	sub_byte(data);
	shift_row(data);
	add_rk(data, rk+(nr+1)*16);
}

static void aes_128_ecb_decrypt(struct aes_opmod *opmod, unsigned char *data)
{
	const size_t nr = 9;
	unsigned char rk[16*(nr+2)], rc=1;
	size_t r=0, i;
	memcpy(rk, opmod->context, 16);
	for(i=0; i<(nr+1); ++i)
		calc_new_rk(rk + i*16, &rc, rk + (i+1)*16);
	add_rk(data, rk+(nr+1)*16);
	for(r=0; r<nr; ++r) {
		invshift_row(data);
		invsub_byte(data);
		add_rk(data, rk+(nr-r)*16);
		invmix_column(data);
	}
	invshift_row(data);
	invsub_byte(data);
	add_rk(data, rk);
}

/**
 * create_aes_opmod() - creates aes operation mod
 * @bit: bit size, AES_BIT_*
 * @opmod: opmod, AES_OPMOD_*
 */
struct aes_opmod *aes_create_opmod(int bit, int mod)
{
	struct aes_opmod *opmod = NULL;
	switch(bit) {
	case AES_BIT_128:
		switch(mod) {
		case AES_OPMOD_ECB:
			opmod = malloc(sizeof(*opmod) + 16);
			opmod->bs = 16;
			opmod->padop = NULL;
			opmod->init = aes_128_ecb_init;
			opmod->enc = aes_128_ecb_encrypt;
			opmod->dec = aes_128_ecb_decrypt;
			break;
		}
	}
	return opmod;
}

/**
 * aes_enc() - encrypts plaintext using given aes_opmod instance
 * @opmod: opmod instance
 * @plain: plaintext
 * @len: plaintext length
 * @cipher: ciphertext (out)
 * @key: key (size should be consistent with opmod)
 * @iv: Initialization Vector (can be null, size should be consistent with opmod)
 *
 * cipher argument should have enough space to store the result,
 * the result takes at least len bytes, and may take up to a block size more if
 * padding is required.
 */
void aes_enc(struct aes_opmod *opmod, const unsigned char *plain, size_t len,
		unsigned char *cipher, const unsigned char *key, const unsigned char *iv)
{
	size_t num_blocks, i;
	memcpy(cipher, plain, len);
	if (opmod->padop)
		len = opmod->padop(cipher, len, opmod->bs);
	num_blocks = len/opmod->bs;
	opmod->init(opmod, key, iv);
	for (i=0; i<num_blocks; ++i) {
		opmod->enc(opmod, cipher + i*opmod->bs);
	}
}

/**
 * aes_dec() - decrypts ciphertext using given aes_opmod instance
 * @opmod: opmod instance
 * @cipher: ciphertext
 * @len: plaintext length
 * @plain: plaintext (out)
 * @key: key (size should be consistent with opmod)
 * @iv: Initialization Vector (can be null, size should be consistent with opmod)
 *
 * plain argument should have enough space to store the result,
 * the result takes at least len bytes, and may take up to a block size more if
 * padding is required.
 */
void aes_dec(struct aes_opmod *opmod, const unsigned char *cipher, size_t len,
		unsigned char *plain, const unsigned char *key, const unsigned char *iv)
{
	size_t num_blocks, i;
	memcpy(plain, cipher, len);
	if (opmod->padop)
		len = opmod->padop(plain, len, opmod->bs);
	num_blocks = len/opmod->bs;
	opmod->init(opmod, key, iv);
	for (i=0; i<num_blocks; ++i) {
		opmod->dec(opmod, plain + i*opmod->bs);
	}
}










