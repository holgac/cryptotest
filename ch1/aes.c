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
#include "../impl/aes.h"

static void aes_encrypt(int argc, char **argv);
static void aes_encrypt_hex(int argc, char **argv);
static void aes_decrypt(int argc, char **argv);
static void aes_decryptf(int argc, char **argv);
static void aes_decryptfcbc(int argc, char **argv);
static void aes_analyze(int argc, char **argv);
static void aes_oracle(int argc, char **argv);
static void aes_analyzes(int argc, char **argv);

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
	strcpy(cmd->cmd, "oracle");
	cmd->argcnt = 0;
	cmd->perform = aes_oracle;
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
	to_base64(cipher, len, cb64);
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
	to_base64(cipher, len, cb64);
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
	from_base64(cb64, len, cipher);
	len = 3 * len / 4;
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
	from_base64(cb64, len, cipher);
	len = 3 * len / 4;
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
	size_t i, prelen, suflen, len, repseq;
	unsigned char *plain, *cipher;
	srand(time(NULL));
	if(rand()%2) {
		mode = AES_OPMOD_CBC;
	}
	for(i=0; i<16; ++i) {
		iv[i] = rand()%256;
		key[i] = rand()%256;
	}
	prelen = 5 + rand()%6;
	suflen = 5 + rand()%6;
	/* At least 4 identical blocks */
	len = prelen+suflen+11+16*4;
	plain = alloca(len);
	memset(plain, 'A', len);
	cipher = alloca(len+16);
	opmod = aes_create_opmod(AES_BIT_128, mode);
	opmod->padop = pad_pkcs7;
	for(i=0; i<prelen; ++i)
		plain[i] = rand()%256;
	for(i=0; i<suflen; ++i)
		plain[len-i-1] = rand()%256;
	aes_enc(opmod, plain, len, cipher, key, iv);
	repseq = aes_repeated_seqs(cipher, len);
	if(repseq>= 4)
		guess = AES_OPMOD_ECB;
	else
		guess = AES_OPMOD_CBC;
	if(guess != mode)
		printf("Guessed %d, was actually %d\n", guess, mode);
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
	from_base64(ub64, lenu, salted_plain+len);
	clen = pad_pkcs7(salted_plain, clen, 16);
	
	opmod = aes_create_opmod(AES_BIT_128, AES_OPMOD_ECB);
	aes_enc(opmod, salted_plain, clen, cipher, key, NULL);
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
	unsigned char key[16], *cur_cipher;
	size_t block_size, i, j, ulen;
	unsigned char *decrypted_salt, *cipher;
	for(i=0; i<16; ++i)
		key[i] = rand()%256;
	/* Find block size */
	block_size = aes_block_size(key, &ulen);
	printf("Block size: %lu, ulen %lu\n", block_size, ulen);
	decrypted_salt = malloc(ulen + 4*block_size + 1);
	memset(decrypted_salt, 'A', block_size);
	cipher = malloc(ulen + 4*block_size);
	cur_cipher = alloca(block_size);
	if(aes_guess_mod(key, block_size, ulen) == AES_OPMOD_ECB)
		printf("Detected ECB\n");
	for(i=0; i<block_size; ++i) {
		unknown_cipher(decrypted_salt+i+1, block_size-i-1, key, cipher, NULL);
		memcpy(cur_cipher, cipher, block_size);
		for(j=0; j<256; ++j) {
			decrypted_salt[block_size + i] = j;
			unknown_cipher(decrypted_salt+i+1, block_size, key, cipher, NULL);
			if(memcmp(cur_cipher, cipher, block_size) == 0) {
				break;
			}
		}
	}
	for(i=block_size; i<ulen; ++i) {
		unknown_cipher(decrypted_salt, block_size - (i%block_size) - 1, key, cipher, NULL);
		memcpy(cur_cipher, cipher + block_size * (i/block_size), block_size);
		for(j=0; j<256; ++j) {
			decrypted_salt[block_size + i] = j;
			unknown_cipher(decrypted_salt+i+1, block_size, key, cipher, NULL);
			if(memcmp(cipher, cur_cipher, block_size) == 0) {
				break;
			}
		}
		if(j == 256)
			printf("NO MATCH AT %lu\n", i);
	}
	decrypted_salt[block_size + i] = 0;
	printf("Salt:\n%s\n", (char *)(decrypted_salt+block_size));
	free(decrypted_salt);
	free(cipher);
}









