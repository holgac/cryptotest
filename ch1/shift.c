#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "../rypto.h"

static void shift_encrypt(int argc, char **argv);
static void shift_decrypt(int argc, char **argv);
static void shift_analyze(int argc, char **argv);

struct command *construct_shift_cmd()
{
	struct command *shift, *cmd;
	shift = malloc(sizeof(struct command));
	strcpy(shift->cmd, "shift");
	cmd = malloc(sizeof(struct command));
	shift->child = cmd;
	shift->next = 0;
	strcpy(cmd->cmd, "encrypt");
	cmd->argcnt = 2;
	cmd->perform = shift_encrypt;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "decrypt");
	cmd->argcnt = 2;
	cmd->perform = shift_decrypt;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "analyze");
	cmd->argcnt = 1;
	cmd->perform = shift_analyze;
	cmd->child = 0;
	cmd->next = 0;
	return shift;
}

static void shift_encrypt(int argc, char **argv)
{
	unsigned char *result;
	size_t datalen, keylen;
	datalen = strlen(argv[0]);
	keylen = strlen(argv[1]);
	result = alloca(datalen+1);
	result[datalen] = 0;
	cipher_shift((unsigned char *)argv[0], datalen,
			(unsigned char *)argv[1], keylen,
			alphabet_en, ALPHABET_EN_LEN, result);
	printf("%s\n", result);
}


static void shift_decrypt(int argc, char **argv)
{
	char *newargv[2];
	size_t keylen, i;
	newargv[0] = argv[0];
	keylen = strlen(argv[1]);
	newargv[1] = alloca(keylen+1);
	for(i=0; i<keylen; ++i) {
		int newval = 100*ALPHABET_EN_LEN - argv[1][i];
		newargv[1][i] = newval % ALPHABET_EN_LEN;
	}
	newargv[1][keylen] = 0;
	shift_encrypt(argc, newargv);
}

static void shift_analyze(int argc, char **argv)
{
	size_t i, datalen;
	char *plain;
	unsigned char shiftdata[1];
	double freqmap[FREQMAP_LEN];
	datalen = strlen(argv[0]);
	plain = alloca(datalen+1);
	plain[datalen] = 0;
	for(i=0; i<ALPHABET_EN_LEN; ++i) {
		double score;
		shiftdata[0] = i;
		cipher_shift((unsigned char *)argv[0], datalen, 
				shiftdata, 1, alphabet_en, ALPHABET_EN_LEN,
				(unsigned char *)plain);
		freqmap_calc((unsigned char *)plain, datalen, freqmap);
		score = freqmap_comp(freqmap, freqmap_en);
		if(score > 0.05) {
			printf("Possible K = %ld, plaintext: %s\n", i, plain);
		}
	}
}










