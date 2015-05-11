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
	unsigned char *cipher;
	size_t datalen;
	size_t i;
	char *cipher_b64;
	datalen = strlen(argv[0]);
	cipher = alloca(datalen);
	cipher_aes((unsigned char *)argv[0], datalen, (unsigned char *)argv[1], cipher);
	printf("Cipher: ");
	for(i=0; i<datalen; ++i)
		printf("%02x", (unsigned int)cipher[i]);
	cipher_b64 = alloca(4 * datalen / 3 + 1);
	to_base64(cipher, datalen, cipher_b64);
	cipher_b64[4*datalen / 3] = 0;
	printf("\nBase64: %s\n", cipher_b64);
}

static void aes_encrypt_hex(int argc, char **argv)
{
	unsigned char *cipher, *data, *key;
	size_t datalen;
	size_t i;
	char *cipher_b64;
	datalen = strlen(argv[0])/2;
	data = alloca(datalen);
	from_hex(argv[0], datalen*2, data);
	key = alloca(17);
	from_hex(argv[1], 32, key);
	cipher = alloca(datalen);
	cipher_aes(data, datalen, key, cipher);
	printf("Cipher: ");
	for(i=0; i<datalen; ++i)
		printf("%02x", (unsigned int)cipher[i]);
	cipher_b64 = alloca(4 * datalen / 3 + 1);
	to_base64(cipher, datalen, cipher_b64);
	cipher_b64[4*datalen / 3] = 0;
	printf("\nBase64: %s\n", cipher_b64);
}

static void aes_decrypt(int argc, char **argv)
{
	unsigned char *plain, *cipher, *key;
	size_t cipherlen;
	size_t i;
	cipherlen = strlen(argv[0])/2;
	cipher = alloca(cipherlen);
	from_hex(argv[0], cipherlen*2, cipher);
	key = alloca(17);
	from_hex(argv[1], 32, key);
	plain = alloca(cipherlen+1);
	decipher_aes(cipher, cipherlen, key, plain);
	printf("Plain hex: ");
	for(i=0; i<cipherlen; ++i)
		printf("%02x", (unsigned int)plain[i]);
	plain[cipherlen] = 0;
	printf("\nPlaintext: ^%s$\n", (char *)plain);
}

static void aes_decryptf(int argc, char **argv)
{
	int fd;
	struct stat filestat;
	char *base64;
	unsigned char *plain;
	size_t datalen, keylen;
	unsigned char *data;
	unsigned char *key;
	
	fd = open(argv[0], O_RDONLY);
	fstat(fd, &filestat);
	base64 = alloca(filestat.st_size);
	datalen = read(fd, base64, filestat.st_size);
	data = alloca(3 * datalen / 4);
	from_base64(base64, datalen, data);
	datalen = 3 * datalen / 4;
	plain = alloca(datalen+1);
	plain[datalen] = 0;
	keylen = strlen(argv[1]);
	key = (unsigned char *)argv[1];
	decipher_aes(data, datalen, key, plain);
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











