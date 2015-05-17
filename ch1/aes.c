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
static void aes_analyze(int argc, char **argv);

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
}

static size_t aes_repeated_seqs(const char *buffer, size_t len)
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
		repeated = aes_repeated_seqs(buffer, cipherlen);
		if(repeated > most_repeated) {
			printf("%lu repetitions at line %lu\n", repeated, line);
			most_repeated = repeated;
			strcpy(best_buf, buffer);
		}
	}
	printf("Cipher: %s\n", best_buf);
}











