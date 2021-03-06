#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "../rypto.h"
#include "../impl/util.h"
#include "../impl/aes.h"

static void aes_encrypt(int argc, char **argv);
static void aes_encrypt_hex(int argc, char **argv);
static void aes_decrypt(int argc, char **argv);
static void aes_decryptf(int argc, char **argv);
static void aes_decryptfcbc(int argc, char **argv);
static void aes_analyze(int argc, char **argv);
static void aes_oracle(int argc, char **argv);
static void aes_cbcoracle(int argc, char **argv);
static void aes_analyzes(int argc, char **argv);
static void aes_analyzeh(int argc, char **argv);
static void aes_cutpaste(int argc, char **argv);
static void aes_bitflip(int argc, char **argv);
static void aes_encctr(int argc, char **argv);
static void aes_encctrhex(int argc, char **argv);
static void aes_ctrstat(int argc, char **argv);
static void aes_breakctr(int argc, char **argv);

struct command *construct_aes_cmd()
{
	struct command *aes, *cmd;
	aes = malloc(sizeof(struct command));
	strcpy(aes->cmd, "aes");
	cmd = malloc(sizeof(struct command));
	aes->child = cmd;
	aes->next = 0;
	strcpy(cmd->cmd, "encrypt");
	cmd->argcnt = 2;
	cmd->perform = aes_encrypt;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "encrypt-hex");
	cmd->argcnt = 2;
	cmd->perform = aes_encrypt_hex;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "decrypt");
	cmd->argcnt = 2;
	cmd->perform = aes_decrypt;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "decryptf");
	cmd->argcnt = 2;
	cmd->perform = aes_decryptf;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "decryptfcbc");
	cmd->argcnt = 3;
	cmd->perform = aes_decryptfcbc;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "cbcoracle");
	cmd->argcnt = 0;
	cmd->perform = aes_cbcoracle;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "oracle");
	cmd->argcnt = 0;
	cmd->perform = aes_oracle;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "breakctr");
	cmd->argcnt = 1;
	cmd->perform = aes_breakctr;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "ctrstat");
	cmd->argcnt = 1;
	cmd->perform = aes_ctrstat;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "encctrhex");
	cmd->argcnt = 2;
	cmd->perform = aes_encctrhex;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "encctr");
	cmd->argcnt = 1;
	cmd->perform = aes_encctr;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "bitflip");
	cmd->argcnt = 0;
	cmd->perform = aes_bitflip;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "cutpaste");
	cmd->argcnt = 0;
	cmd->perform = aes_cutpaste;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "analyzeh");
	cmd->argcnt = 0;
	cmd->perform = aes_analyzeh;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "analyzes");
	cmd->argcnt = 0;
	cmd->perform = aes_analyzes;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "analyze");
	cmd->argcnt = 1;
	cmd->perform = aes_analyze;
	cmd->child = 0;
	cmd->next = 0;
	return aes;
}

static void aes_encrypt(int argc, char **argv)
{
	struct aes_opmod *opmod;
	unsigned char *plain, *key, *cipher;
	size_t len;
	char *chex, *cb64;

	plain = (unsigned char *)argv[0];
	key = (unsigned char *)argv[1];
	len = strlen(argv[0]);
	cipher = alloca(len);
	chex = alloca(len*2 + 1);
	chex[len*2] = 0;
	cb64 = alloca(4*len/3+1);
	cb64[4*len/3] = 0;
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_ECB);
	aes_enc(opmod, plain, len, cipher, key, NULL);
	to_hex(cipher, len, chex);
	to_base64(cipher, len, cb64, NULL);
	printf("Cipher: %s\nBase64: %s\n", chex, cb64);
	free(opmod);
}

static void aes_encrypt_hex(int argc, char **argv)
{
	struct aes_opmod *opmod;
	unsigned char *cipher, *plain, *key;
	size_t len;
	char *chex, *cb64;

	len = strlen(argv[0])/2;
	plain = alloca(len);
	from_hex(argv[0], len*2, plain);
	key = alloca(17);
	from_hex(argv[1], 32, key);
	cipher = alloca(len);
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_ECB);
	aes_enc(opmod, plain, len, cipher, key, NULL);
	chex = alloca(len*2+1);
	cb64 = alloca(4 * len / 3 + 1);
	to_hex(cipher, len, chex);
	to_base64(cipher, len, cb64, NULL);
	printf("Cipher: %s\nBase64: %s\n", chex, cb64);
	free(opmod);
}

static void aes_decrypt(int argc, char **argv)
{
	struct aes_opmod *opmod;
	unsigned char *plain, *cipher, *key;
	size_t cipherlen;
	char *plainhex;
	cipherlen = strlen(argv[0])/2;
	cipher = alloca(cipherlen);
	from_hex(argv[0], cipherlen*2, cipher);
	key = alloca(17);
	from_hex(argv[1], 32, key);
	plain = alloca(cipherlen+1);
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_ECB);
	aes_dec(opmod, cipher, cipherlen, plain, key, NULL);
	plainhex = alloca(cipherlen*2+1);
	to_hex(plain, cipherlen, plainhex);
	plain[cipherlen] = 0;
	printf("Plain hex: %s\nPlain text: %s\n", plainhex, (char *)plain);
	free(opmod);
}

static void aes_decryptf(int argc, char **argv)
{
	struct aes_opmod *opmod;
	int fd;
	struct stat filestat;
	char *cb64;
	unsigned char *plain;
	size_t len;
	unsigned char *cipher, *key;

	fd = open(argv[0], O_RDONLY);
	fstat(fd, &filestat);
	cb64 = alloca(filestat.st_size);
	len = read(fd, cb64, filestat.st_size);
	cipher = alloca(3 * len / 4);
	from_base64(cb64, len, cipher, &len);
	plain = alloca(len+1);
	plain[len] = 0;
	key = (unsigned char *)argv[1];

	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_ECB);
	aes_dec(opmod, cipher, len, plain, key, NULL);
	printf("Plain: %s\n", plain);
	free(opmod);
}

static void aes_decryptfcbc(int argc, char **argv)
{
	struct aes_opmod *opmod;
	int fd;
	struct stat filestat;
	char *cb64;
	unsigned char *plain;
	size_t len;
	unsigned char *cipher, *key, iv[16];
	fd = open(argv[0], O_RDONLY);
	fstat(fd, &filestat);
	cb64 = alloca(filestat.st_size);
	len = read(fd, cb64, filestat.st_size);
	cipher = alloca(3 * len / 4);
	from_base64(cb64, len, cipher, &len);
	plain = alloca(len+1);
	plain[len] = 0;
	key = (unsigned char *)argv[1];
	from_hex(argv[2], 32, iv);

	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_CBC);
	aes_dec(opmod, cipher, len, plain, key, iv);
	printf("Plain: %s\n", plain);
	free(opmod);
}

static size_t aes_repeated_seqs(const unsigned char *buffer, size_t len)
{
	size_t repeated = 1;
	size_t i, j;
	size_t num_blocks = len / 16;
	for(i=0; i<num_blocks; ++i) {
		for(j=i+1; j<num_blocks; ++j) {
			if(memcmp(buffer+i*16, buffer+j*16, 16) == 0) {
				repeated += 1;
				break;
			}
		}
	}
	return repeated;
}

static size_t aes_repeated_seqs_hex(const char *buffer, size_t len)
{
	size_t repeated = 1;
	size_t i, j;
	size_t num_blocks = len / 32;
	for(i=0; i<num_blocks; ++i) {
		for(j=i+1; j<num_blocks; ++j) {
			if(memcmp(buffer+i*32, buffer+j*32, 32) == 0) {
				repeated += 1;
				break;
			}
		}
	}
	return repeated;
}

static void aes_analyze(int argc, char **argv)
{
	FILE *f;
	char buffer[1024], best_buf[1024];
	size_t cipherlen;
	size_t most_repeated = 1, repeated, line=0;
	f = fopen(argv[0], "r");
	while(!feof(f)) {
		if(NULL == fgets(buffer, 1024, f))
			break;
		line++;
		cipherlen = strlen(buffer);
		repeated = aes_repeated_seqs_hex(buffer, cipherlen);
		if(repeated > most_repeated) {
			printf("%lu repetitions at line %lu\n", repeated, line);
			most_repeated = repeated;
			strcpy(best_buf, buffer);
		}
	}
	printf("Cipher: %s\n", best_buf);
}

static void aes_oracle(int argc, char **argv)
{
	int mode = AES_OPMOD_ECB, guess;
	struct aes_opmod *opmod;
	unsigned char iv[16], key[16];
	size_t prelen, suflen, len, repseq;
	unsigned char *plain, *cipher;
	if(rand()%2) {
		mode = AES_OPMOD_CBC;
	}
	fill_random(iv, 16);
	fill_random(key, 16);
	prelen = 5 + rand()%6;
	suflen = 5 + rand()%6;
	/* At least 4 identical blocks */
	len = prelen+suflen+11+16*4;
	plain = alloca(len);
	memset(plain, 'A', len);
	cipher = alloca(len+16);
	opmod = aes_create_opmod(AES_BIT_128, mode);
	opmod->padop = pad_pkcs7;
	fill_random(plain, prelen);
	fill_random(plain+len-suflen+1, suflen);
	aes_enc(opmod, plain, len, cipher, key, iv);
	repseq = aes_repeated_seqs(cipher, len);
	if(repseq>= 4)
		guess = AES_OPMOD_ECB;
	else
		guess = AES_OPMOD_CBC;
	if(guess != mode)
		printf("Guessed %d, was actually %d\n", guess, mode);
	else
		printf("Correct guess!\n");
	free(opmod);
}

static void unknown_cipherh(const unsigned char *plain, size_t len, 
		const unsigned char *key, unsigned char *cipher, size_t *clen_out)
{
	char *ub64="Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
		"YnkK";
	struct aes_opmod *opmod;
	size_t lenu, lenub, clen, randlen;
	unsigned char *salted_plain;
	randlen = 32 + rand()%32;
	lenu = strlen(ub64);
	lenub = 3 * lenu / 4;
	clen = lenub + len + randlen;
	salted_plain = alloca(clen + 16);
	fill_random(salted_plain, randlen);
	memcpy(salted_plain + randlen, plain, len);
	from_base64(ub64, lenu, salted_plain+len+randlen, NULL);
	clen = pad_pkcs7(salted_plain, clen, 16);
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_ECB);
	aes_enc(opmod, salted_plain, clen, cipher, key, NULL);
	free(opmod);
	if(clen_out != NULL)
		*clen_out = clen;
}

static void unknown_cipher(const unsigned char *plain, size_t len, 
		const unsigned char *key, unsigned char *cipher, size_t *clen_out)
{
	char *ub64="Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
		"YnkK";
	struct aes_opmod *opmod;
	size_t lenu, lenub, clen;
	unsigned char *salted_plain;
	lenu = strlen(ub64);
	lenub = 3 * lenu / 4;
	clen = lenub + len;
	salted_plain = alloca(clen + 16);
	memcpy(salted_plain, plain, len);
	from_base64(ub64, lenu, salted_plain+len, NULL);
	clen = pad_pkcs7(salted_plain, clen, 16);
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_ECB);
	aes_enc(opmod, salted_plain, clen, cipher, key, NULL);
	free(opmod);
	if(clen_out != NULL)
		*clen_out = clen;
}

static size_t aes_block_size(const unsigned char *key, size_t *ulen)
{
	size_t first, i, cur;
	unsigned char plain[4096];
	unsigned char cipher[8192];
	plain[0] = 1;
	unknown_cipher(plain, 1, key, cipher, &first);
	for(i=2; i<4096; ++i) {
		unknown_cipher(plain, i, key, cipher, &cur);
		if(cur != first) {
			*ulen = first-i;
			return cur-first;
		}
	}
	return 0;
}

static int aes_guess_mod(const unsigned char *key, size_t bs, size_t ulen)
{
	size_t plainlen, cipherlen;
	unsigned char *plain;
	unsigned char *cipher;
	plainlen = 3*bs;
	plain = alloca(plainlen);
	memset(plain, 'A', plainlen);
	cipher = alloca(ulen + 4*bs);
	unknown_cipher(plain, plainlen, key, cipher, &cipherlen);
	if(memcmp(cipher, cipher+bs, bs) == 0)
		return AES_OPMOD_ECB;
	return AES_OPMOD_CBC;
}

static void aes_analyzes(int argc, char **argv)
{
	size_t block_size, i, j, ulen;
	unsigned char key[16], *target_cipher, *decrypted_salt, *cipher;
	unsigned char *def_ciphers[16];
	fill_random(key, 16);
	/* Find block size */
	block_size = aes_block_size(key, &ulen);
	printf("Block size: %lu, ulen %lu\n", block_size, ulen);
	decrypted_salt = malloc(ulen + 4*block_size + 1);
	memset(decrypted_salt, 'A', block_size);
	for(i=0; i<16; ++i) {
		def_ciphers[i] = malloc(ulen + block_size);
		unknown_cipher(decrypted_salt, (block_size-i) % block_size, key, def_ciphers[i], NULL);
	}
	cipher = malloc(ulen + 4*block_size);
	if(aes_guess_mod(key, block_size, ulen) == AES_OPMOD_ECB)
		printf("Detected ECB\n");
	for(i=0; i<block_size; ++i) {
		target_cipher = def_ciphers[(i+1)%block_size];
		for(j=0; j<256; ++j) {
			decrypted_salt[block_size + i] = j;
			unknown_cipher(decrypted_salt+i+1, block_size, key, cipher, NULL);
			if(memcmp(target_cipher, cipher, block_size) == 0) {
				break;
			}
		}
	}
	for(i=block_size; i<ulen; ++i) {
		target_cipher = def_ciphers[(i+1)%block_size] + block_size * (i/block_size);
		for(j=0; j<256; ++j) {
			decrypted_salt[block_size + i] = j;
			unknown_cipher(decrypted_salt+i+1, block_size, key, cipher, NULL);
			if(memcmp(cipher, target_cipher, block_size) == 0) {
				break;
			}
		}
		if(j == 256) {
			printf("NO MATCH AT %lu\n", i);
			exit(-1);
		}
	}
	decrypted_salt[block_size + i] = 0;
	printf("Salt:\n%s\n", (char *)(decrypted_salt+block_size));
	free(decrypted_salt);
	free(cipher);
	for(i=0; i<16; ++i)
		free(def_ciphers[i]);
}

static void profile_for(const char *email, unsigned char *res, size_t *len)
{
	const char *prefix = "email=";
	const char *suffix = "&uid=10&role=user";
	char *tok;
	size_t reslen = strlen(prefix), toklen;
	char em[256];
	strcpy(em, email);
	memcpy(res, prefix, reslen);
	for(tok=strtok(em, "&="); tok; tok=strtok(NULL, "&=")) {
		toklen = strlen(tok);
		memcpy(res+reslen, tok, toklen);
		reslen += toklen;
	}
	toklen = strlen(suffix);
	memcpy(res+reslen, suffix, toklen);
	reslen += toklen;
	res[reslen] = 0;
	if(len)
		*len = reslen;
}

static void encode_profile(const char *email, const unsigned char *key, unsigned char *res, size_t *outlen)
{
	struct aes_opmod *opmod;
	unsigned char tmp[1024];
	size_t len;
	profile_for(email, tmp, &len);
	len = pad_pkcs7(tmp, len, 16);
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_ECB);
	aes_enc(opmod, tmp, len, res, key, NULL);
	free(opmod);
	if(outlen)
		*outlen = len;
}

static void decode_profile(const unsigned char *cipher, size_t cipherlen, const unsigned char *key, char *res, size_t *outlen)
{
	struct aes_opmod *opmod;
	ssize_t len;
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_ECB);
	aes_dec(opmod, cipher, cipherlen, (unsigned char *)res, key, NULL);
	len = unpad_pkcs7((unsigned char *)res, cipherlen, 16);
	free(opmod);
	if(len == -1) {
		printf("Corrupt cipher!\n");
		exit(-1);
	}
	if(outlen)
		*outlen = len;
}

static void aes_cutpaste(int argc, char **argv)
{
	unsigned char res[1024];
	unsigned char key[16];
	size_t len, i, cipherlen, suflen;
	unsigned char suffix[26];
	char decoded[1024];
	memcpy(suffix, "fo@bar.comadmin", 15);
	for(i=15; i<26; ++i)
		suffix[i] = 11;
	fill_random(key, 16);
	profile_for("ah&=&met@mehmet.com", res, &len);
	profile_for("a&hme&&&&t@mehmet.com", res+512, NULL);
	if(memcmp(res, res+512, len) != 0) {
		printf("Error in character escaping!\n");
		exit(-1);
	}
	encode_profile("AAAAAAAAAAAAA", key, res, &cipherlen);
	encode_profile((char *)suffix, key, res+512, &suflen);
	memmove(res+cipherlen-16, res+512+16, 16);
	decode_profile(res, cipherlen, key, decoded, &len);
	decoded[len] = 0;
	printf("Decoded: %s\n", decoded);
}

static size_t aes_occ3(unsigned char *cipher, size_t cipherlen, size_t block_size)
{
	size_t i, num_blocks;
	num_blocks = cipherlen / block_size - 2;
	for(i=0; i<num_blocks; ++i) {
		if(memcmp(cipher + i*block_size, cipher + (i+1)*block_size, block_size) == 0) {
			if(memcmp(cipher + i*block_size, cipher + (i+2)*block_size, block_size) == 0)
				return i;
		}
	}
	return cipherlen; 
}

static void aes_fillb(unsigned char *cipher, size_t cipherlen, unsigned char *cipher_a, 
		size_t occ_a, size_t block_size, unsigned char *cipher_b)
{
	unsigned char *cip_a_pos;
	size_t occ_na, i, occ_diff;
	cip_a_pos = memmem(cipher + block_size*(occ_a+3), cipherlen - block_size*(occ_a+3),
			cipher_a, block_size);
	if(cip_a_pos == NULL) {
		printf("Cannot find cipher_a\n");
		exit(-1);
	}
	occ_na = (cip_a_pos - cipher)/block_size;
	occ_diff = occ_na - occ_a + 2;
	for(i=occ_na+1; i < occ_a + 20; ++i) {
		memcpy(cipher_b + (i-occ_na-1)*block_size, cipher + i*block_size, block_size);
	}
	for(i=occ_a+3; i<occ_na; ++i) {
		memcpy(cipher_b + (i-occ_na+16)*block_size, cipher + i*block_size, block_size);
	}
}

static void aes_fillcs(unsigned char *cipher, unsigned char *cipher_salt[16],
		unsigned char *key, unsigned char *test_plain, size_t block_size,
		unsigned char *cipher_a, unsigned char *cipher_b)
{
	size_t found_cs = 0, outlen, occ_a, found_idx, target_idx;
	while(found_cs < 16) {
		unknown_cipherh(test_plain, 1 + block_size*5, key, cipher, &outlen);
		occ_a = ((unsigned char *)memmem(cipher, outlen, cipher_a, block_size) - cipher) / block_size;
		if(memcmp(cipher+(occ_a+3)*block_size, cipher_a, block_size) == 0)
			found_idx = 0;
		else {
			for(found_idx=1; found_idx<16; ++found_idx) {
				if(memcmp(cipher+(occ_a+3)*block_size, cipher_b+found_idx*block_size, block_size) == 0) {
					break;
				}
			}
		}
		target_idx = (found_idx+1) % 16;
		if(cipher_salt[target_idx] == NULL) {
			cipher_salt[target_idx] = malloc(outlen - (occ_a+4) * block_size);
			if(found_idx == 0 || target_idx == 0) {
				memcpy(cipher_salt[target_idx], cipher + (occ_a+5)*block_size, outlen - (occ_a+5)*block_size);
			} else {
				memcpy(cipher_salt[target_idx], cipher + (occ_a+4)*block_size, outlen - (occ_a+4)*block_size);
			}
			found_cs++;
		}
	}
}

static void aes_decrypt_salt_16(unsigned char *cipher, unsigned char *cipher_salt[16],
		unsigned char *test_plain, unsigned char *cipher_a, unsigned char *cipher_b,
		unsigned char *key, size_t block_size, unsigned char *decrypted_salt)
{
	size_t occ_a, salt_i, i, j, outlen, found_idx;
	ssize_t g;
	unsigned char *found_block;
	/* printf("Finding salt[0]\n"); */
	memset(test_plain + 5*block_size+1, 'A', 16*(block_size+1));
	for(g=0; g!=256; ++g) {
		for(i=0; i<16; ++i) {
			test_plain[5*block_size+1 + i*(block_size+1)] = g;
		}
		unknown_cipherh(test_plain, 5*block_size + 1 + (block_size+1)*16,
				key, cipher, &outlen);
		occ_a = ((unsigned char *)memmem(cipher, outlen, cipher_a, block_size)
				- cipher) / block_size;
		if(memcmp(cipher + (occ_a+3)*block_size, cipher_a, block_size) == 0)
			found_idx = 0;
		else
			for(found_idx=1; found_idx<16; ++found_idx)
				if(memcmp(cipher + (occ_a+3)*block_size,
							cipher_b+found_idx*block_size, block_size) == 0)
					break;
		if(found_idx == 0)
			found_block = cipher + (occ_a + 19)*block_size;
		else if(found_idx == 15)
			found_block = cipher + (occ_a + 20)*block_size;
		else
			found_block = cipher + (occ_a + 18 - found_idx) * block_size;
		if(memcmp(found_block, cipher_salt[15], block_size) == 0) {
			/* printf("\tFound salt[0] = %ld (%c)\n", g, (char)g); */
			decrypted_salt[0] = g;
			break;
		}
	}
	/* actually 64A || B || 16A part is no longer necessary */
	for(salt_i=1; salt_i < 16; ++salt_i) {
		/* printf("Finding salt[%lu]\n", salt_i); */
		memset(test_plain + 5*block_size+1, 'A', 16*(block_size+1));
		for(i=0; i<16; ++i)
			for(j=0; j<salt_i; ++j)
				test_plain[5*block_size+1 + i*(block_size+1) + j] = decrypted_salt[j];
		for(g=0; g!=256; ++g) {
			for(i=0; i<16; ++i)
				test_plain[5*block_size+1 + i*(block_size+1) + salt_i] = g;
			unknown_cipherh(test_plain, 5*block_size + 1 + (block_size+1)*16,
					key, cipher, &outlen);
			found_block = memmem(cipher, outlen, cipher_salt[16-salt_i], block_size);
			if(found_block == NULL) {
				g--;
				continue;
			}
			found_block -= block_size;
			if(memcmp(found_block, cipher_salt[15-salt_i], block_size) == 0) {
				/* printf("\tFound salt[%lu] = %ld (%c)\n", salt_i, g, (char)g); */
				decrypted_salt[salt_i] = g;
				break;
			}
		}
		if(g == 256)
			salt_i--;
	}
}

static void aes_decrypt_salt(unsigned char *cipher, unsigned char *cipher_salt[16],
		unsigned char *test_plain, unsigned char *cipher_a, unsigned char *cipher_b,
		unsigned char *key, size_t block_size, unsigned char *decrypted_salt,
		size_t salt_len)
{
	size_t salt_i, i, outlen;
	ssize_t g;
	unsigned char *match, *anchor, *target;
	/* find first 16 bytes of salt */
	aes_decrypt_salt_16(cipher, cipher_salt, test_plain, cipher_a, cipher_b,
			key, block_size, decrypted_salt);
	memset(test_plain, 'A', block_size);
	for(salt_i = 16; salt_i<salt_len; ++salt_i) {
		i = (1024 - salt_i)%16;
		anchor = cipher_salt[i] + block_size*((salt_i-1)/block_size);
		i = (1024 - salt_i - 1) % 16;
		match = cipher_salt[i] + block_size*(salt_i/block_size);
		for(i=0; i<17; ++i)
			memcpy(test_plain + block_size + i*(block_size+1), decrypted_salt+salt_i-block_size, block_size);
		for(g=0; g!=256; ++g) {
			for(i=0; i<17; ++i)
				test_plain[i*(block_size+1) + 2*block_size] = g;
			unknown_cipherh(test_plain, block_size + 17*(block_size+1),
					key, cipher, &outlen);
			target = memmem(cipher, outlen, anchor, block_size);
			if(target == NULL) {
				printf("target null %ld when finding %lu\n", g, salt_i);
				exit(-1);
			}
			target -= block_size;
			if(memcmp(target, cipher_a, block_size) == 0) {
				target = memmem(target+2*block_size, outlen, anchor, block_size);
				if(target == NULL) {
					printf("target still null %ld when finding %lu\n", g, salt_i);
					exit(-1);
				}
				target -= block_size;
			}
			if(memcmp(target, match, block_size) == 0) {
				/* printf("\tFound salt[%lu] = %ld (%c)\n", salt_i, g, (char)g); */
				decrypted_salt[salt_i] = g;
				break;
			}
		}
		if(g == 256) {
			printf("Could not detect %lu!\n", salt_i);
			exit(-1);
		}
	}
}

static void aes_analyzeh(int argc, char **argv)
{
	size_t block_size = 16, i, saltlen=138, outlen;
	/* cipher_b[i*16] = E(K, 'A'*i || 'B' || 'A' * (16-i)) */
	/* cipher_a = E(K, 'A'*16) */
	unsigned char key[16], cipher_a[16], cipher_b[16*16];
	/* cipher_salt[i] = E(K, 'A'*i || salt) */
	unsigned char *decrypted_salt, *cipher, *cipher_salt[16];
	unsigned char *test_plain;
	decrypted_salt = malloc(4096);
	cipher = malloc(4096);
	test_plain = malloc(4096);
	fill_random(key, 16);
	memset(test_plain, 'A', 21*block_size);
	memset(cipher_salt, 0, 16 * sizeof(void *));
	for(i=0; i<16; ++i)
		test_plain[(block_size*4) + (block_size+1)*i] = 'B';
	unknown_cipherh(test_plain, (block_size*4) + (16 * (block_size+1)),
			key, cipher, &outlen);
	i = aes_occ3(cipher, outlen, block_size);
	memcpy(cipher_a, cipher+i*block_size, block_size);
	aes_fillb(cipher, outlen, cipher_a, i, block_size, cipher_b);
	aes_fillcs(cipher, cipher_salt, key, test_plain, block_size,
			cipher_a, cipher_b);
	/* find salt */
	aes_decrypt_salt(cipher, cipher_salt, test_plain, cipher_a, cipher_b,
			key, block_size, decrypted_salt, saltlen);
	decrypted_salt[saltlen] = 0;
	printf("Salt:\n%s\n", (char *)decrypted_salt);
	/* free all resources */
	for(i=0; i<16; ++i)
		free(cipher_salt[i]);
	free(decrypted_salt);
	free(cipher);
	free(test_plain);
}

static void format_userdata(const char *userdata, unsigned char *res, size_t *len)
{
	const char *prefix = "comment1=cooking%20MCs;userdata=";
	const char *suffix = ";comment2=\%20like\%20a\%20pound\%20of\%20bacon";
	char *tok;
	size_t reslen = strlen(prefix), toklen;
	char em[256];
	strcpy(em, userdata);
	memcpy(res, prefix, reslen);
	for(tok=strtok(em, ";="); tok; tok=strtok(NULL, ";=")) {
		toklen = strlen(tok);
		memcpy(res+reslen, tok, toklen);
		reslen += toklen;
	}
	toklen = strlen(suffix);
	memcpy(res+reslen, suffix, toklen);
	reslen += toklen;
	res[reslen] = 0;
	if(len)
		*len = reslen;
}

static void encode_userdata(const char *userdata, unsigned char *res, size_t *len,
		unsigned char *key, unsigned char *iv)
{
	size_t udlen;
	struct aes_opmod *opmod;
	unsigned char ud[256];
	format_userdata(userdata, ud, &udlen);
	udlen = pad_pkcs7(ud, udlen, 16);
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_CBC);
	aes_enc(opmod, ud, udlen, res, key, iv);
	free(opmod);
	if(len)
		*len = udlen;
}

static void decode_userdata(const unsigned char *cipher, size_t cipherlen,
		char *res, size_t *len,
		unsigned char *key, unsigned char *iv)
{
	struct aes_opmod *opmod;
	size_t plen;
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_CBC);
	aes_dec(opmod, cipher, cipherlen, (unsigned char *)res, key, iv);
	plen = unpad_pkcs7((unsigned char *)res, cipherlen, 16);
	res[plen] = 0;
	free(opmod);
	if(len)
		*len = plen;
}

static void aes_bitflip(int argc, char **argv)
{
	unsigned char key[16], iv[16], cipher[1024];
	char plain[256];
	size_t len, ilen;
	char *inject_str = ";admin=true";
	char *s;
	ilen = strlen(inject_str);
	memset(plain, 'A', 32);
	plain[32] = 0;
	fill_random(key, 16);
	fill_random(iv, 16);
	encode_userdata(plain, cipher, &len, key, iv);
	xor_arr((unsigned char *)plain, (const unsigned char *)inject_str, ilen);
	xor_arr(cipher+48-ilen, (unsigned char *)plain, ilen);
	// xor_arr(cipher+48-ilen, (const unsigned char *)inject_str, ilen);
	decode_userdata(cipher, len, plain, &len, key, iv);
	printf("plain: %s\n", plain);
	s = strstr(plain, inject_str);
	if(s == NULL) {
		printf("bitflip failed!\n");
		exit(-1);
	}
	if(s[ilen] != ';') {
		printf("corrupt result!\n");
		exit(-1);
	}
	printf("Success!\n");
}

static void aes_cbcoracle_encrypt(size_t idx, const unsigned char *key,
		const unsigned char *iv, unsigned char *out, size_t *outlen)
{
	const char *plaintexts[] = {
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
	};
	const char *cur_text = plaintexts[idx];
	struct aes_opmod *opmod;
	unsigned char raw[1024];
	size_t rawlen;
	int r;
	r = from_base64(cur_text, strlen(cur_text), raw, &rawlen);
	if(r)
		printf("from_base64 failed\n");
	rawlen = pad_pkcs7(raw, rawlen, 16);
	/* for(r=0; r<rawlen; ++r)
		printf("P%d[%d] = %lu (%c)\n", r/16, r%16,
				(size_t)raw[r], (char)raw[r]); */
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_CBC);
	aes_enc(opmod, raw, rawlen, out, key, iv);
	free(opmod);
	if(outlen)
		*outlen = rawlen;
}

static int aes_cbcoracle_checkpad(const unsigned char *cipher, size_t len,
		const unsigned char *key, const unsigned char *iv)
{
	struct aes_opmod *opmod;
	unsigned char plain[1024];
	ssize_t r;
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_CBC);
	aes_dec(opmod, cipher, len, plain, key, iv);
	free(opmod);
	r = unpad_pkcs7(plain, len, 16);
	if(r >= 0)
		return 0;
	return -1;
}

static void aes_cbcoracle_solvepart(size_t idx, const unsigned char *key,
		const unsigned char *def_iv)
{
	unsigned char cipher[1024], plain[1024];
	unsigned char modcipher[32], immediate[16], iv[16];
	unsigned char *xor_block;
	size_t clen, numblocks, curblock, curbyte, i, j;
	memcpy(iv, def_iv, 16);
	aes_cbcoracle_encrypt(idx, key, iv, cipher, &clen);
	numblocks = clen/16;
	for(curblock = numblocks-1; curblock<numblocks; --curblock) {
		if(curblock == 0)
			xor_block = iv;
		else
			xor_block = cipher + (curblock-1)*16;
		/* randomize previous block*/
		fill_random(modcipher, 16);
		memcpy(modcipher + 16, cipher+curblock*16, 16);
		for(i=0; i<16; ++i) {
			curbyte = 15 - i;
			for(j=0; j<i; ++j) {
				modcipher[15-j] = immediate[15-j] ^ (i+1);
			}
			for(j=0; j<256; ++j) {
				modcipher[curbyte] = j;
				if(aes_cbcoracle_checkpad(modcipher, 32, key, iv)
							== 0) {
					if(i==0) {
						modcipher[curbyte-1]++;
						if(aes_cbcoracle_checkpad(modcipher, 32, key, iv)
								!= 0)
							continue;
					}
					immediate[curbyte] = j^(i+1);
					plain[curblock*16 + curbyte] = j^(i+1)^xor_block[curbyte];
					break;
				}
			}
		}
	}
	clen = unpad_pkcs7(plain, clen, 16);
	plain[clen] = 0;
	printf("Plain of %lu: %s\n", idx, (char *)plain);
}

static void aes_cbcoracle(int argc, char **argv)
{
	unsigned char key[16], iv[16];
	size_t i;
	fill_random(key, 16);
	fill_random(iv, 16);
	for(i=0; i<10; ++i)
		aes_cbcoracle_solvepart(i, key, iv);
}

static void aes_encctr(int argc, char **argv)
{
	struct aes_opmod *opmod;
	unsigned char *raw, *res;
	size_t len;
	unsigned char iv[16];
	char *key = "YELLOW SUBMARINE";
	len = strlen(argv[0]);
	raw = malloc(len);
	from_base64(argv[0], len, raw, &len);
	res = malloc(len);
	memset(iv, 0, 16);
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_CTR);
	aes_enc(opmod, raw, len, res, (unsigned char *)key, iv);
	printf("Result: %s\n", (char *)res);
	free(res);
	free(raw);
	free(opmod);
}

static void aes_encctrhex(int argc, char **argv)
{
	struct aes_opmod *opmod;
	unsigned char *raw, *res;
	size_t len;
	unsigned char iv[16], key[16];
	char *reshex;
	from_hex(argv[1], 32, key);
	len = strlen(argv[0]);
	raw = malloc(len);
	from_base64(argv[0], len, raw, &len);
	res = malloc(len);
	memset(iv, 0, 16);
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_CTR);
	aes_enc(opmod, raw, len, res, (unsigned char *)key, iv);
	reshex = malloc(len*2+1);
	to_hex(res, len, reshex);
	printf("%s\n", reshex);
	free(res);
	free(raw);
	free(reshex);
	free(opmod);
}

static void aes_ctrstat(int argc, char **argv)
{
	char buf[1024];
	unsigned char *ciphers[60], raw[1024], *xor_key;
	unsigned char key[16], iv[16];
	FILE *inp;
	size_t i, j, k, len, minlen=1024;
	struct aes_opmod *opmod;
	double freqmap[FREQMAP_LEN], invlen = 1.0 / 60, score, max_score;
	size_t max_score_byte;
	int freq_idx;
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_CTR);
	fill_random(key, 16);
	memset(iv, 0, 16);
	inp = fopen(argv[0], "r");
	for(i=0; i<60; ++i) {
		fgets(buf, 1024, inp);
		len = strlen(buf)-1;
		from_base64(buf, len, raw, &len);
		ciphers[i] = malloc(len);
		aes_enc(opmod, raw, len, ciphers[i], key, iv);
		minlen = min(minlen, len);
	}
	xor_key = malloc(minlen);

	for(i=0; i<minlen; ++i) {
		printf("S[%lu]:\n", i);
		max_score = 0;
		for(j=0; j<256; ++j) {
			for(k=0; k<FREQMAP_LEN; ++k)
				freqmap[k] = 0.0;
			for(k=0; k<60; ++k) {
				freq_idx = get_freqmap_idx(j ^ ciphers[k][i]);
				if(freq_idx != -1)
					freqmap[k] += invlen;
				score = freqmap_comp(freqmap, freqmap_en);
				if(score > max_score) {
					max_score = score;
					max_score_byte = j;
				}
			}
		}
		printf("\t%lu with score %lf\n", max_score_byte, max_score);
		xor_key[i] = max_score_byte;
	}
	
	for(i=0; i<60; ++i) {
		memcpy(buf, ciphers[i], minlen);
		xor_arr((unsigned char *)buf, xor_key, minlen);
		buf[minlen] = 0;
		printf("String %lu: %s\n", i, buf);
		free(ciphers[i]);
	}
	free(xor_key);
	free(opmod);

}

static void aes_breakctr_edit(unsigned char *cipher, size_t idx,
		unsigned char newval, const unsigned char *keystream)
{
	cipher[idx] = newval ^ keystream[idx];
}

static void aes_breakctr(int argc, char **argv)
{
	char *ys = "YELLOW SUBMARINE";
	unsigned char key[16], iv[16];
	struct aes_opmod *opmod;
	unsigned char *keystream, *zero, *cipher, *plain, *cipherb64;
	size_t flen, i;
	unsigned char u;
	memcpy(key, ys, 16);
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_ECB);
	read_file(argv[0], &cipherb64, &flen);
	cipher = malloc(flen);
	from_base64((const char *)cipherb64, flen, cipher, &flen);
	free(cipherb64);
	plain = malloc(flen);
	aes_dec(opmod, cipher, flen, plain, key, NULL);
	free(opmod);
	fill_random(key, 16);
	fill_random(iv, 16);
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_CTR);
	keystream = malloc(flen);
	zero = malloc(flen);
	memset(zero, 0, flen);
	aes_enc(opmod, zero, flen, keystream, key, iv);
	free(opmod);
	free(zero);
	memcpy(cipher, plain, flen);
	xor_arr(cipher, keystream, flen);
	for(i=0; i<flen; ++i) {
		u = cipher[i];
		aes_breakctr_edit(cipher, i, 0, keystream);
		u ^= cipher[i];
		if(u != plain[i]) {
			printf("Wrong guess\n");
			exit(-1);
		}
	}
	plain[flen] = 0;
	printf("Guessed/correct plaintest: %s\n", (char *)plain);
	free(plain);
	free(keystream);
	free(cipher);
}









