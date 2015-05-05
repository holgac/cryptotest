#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "../rypto.h"

static void affine_encrypt(int argc, char **argv);
static void affine_decrypt(int argc, char **argv);
static void affine_analyze(int argc, char **argv);

struct command *construct_affine_cmd()
{
	struct command *affine, *cmd;
	affine = malloc(sizeof(struct command));
	strcpy(affine->cmd, "affine");
	cmd = malloc(sizeof(struct command));
	affine->child = cmd;
	affine->next = 0;
	strcpy(cmd->cmd, "encrypt");
	cmd->argcnt = 3;
	cmd->perform = affine_encrypt;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "decrypt");
	cmd->argcnt = 3;
	cmd->perform = affine_decrypt;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "analyze");
	cmd->argcnt = 1;
	cmd->perform = affine_analyze;
	cmd->child = 0;
	cmd->next = 0;
	return affine;
}

static void affine_encrypt(int argc, char **argv)
{
	unsigned char *result;
	size_t datalen;
	int a, b;
	datalen = strlen(argv[0]);
	result = alloca(datalen+1);
	result[datalen] = 0;
	a = atoi(argv[1]);
	b = atoi(argv[2]);
	cipher_affine((unsigned char *)argv[0], datalen,
			a, b,
			alphabet_en, ALPHABET_EN_LEN, result);
	printf("%s\n", result);
}


static void affine_decrypt(int argc, char **argv)
{
	unsigned char *result;
	size_t datalen;
	int a, b;
	long euclid_res[3];
	datalen = strlen(argv[0]);
	result = alloca(datalen+1);
	result[datalen] = 0;
	a = atoi(argv[1]);
	b = atoi(argv[2]);

	extended_euclid(a, ALPHABET_EN_LEN, euclid_res);
	if(euclid_res[0] != 1) {
		printf("invlid affine parameters\n");
		exit(-1);
	}
	while(euclid_res[1] < 0)
		euclid_res[1] += ALPHABET_EN_LEN;
	a = euclid_res[1];
	b = -1 * a * b;
	while(b < 0)
		b += ALPHABET_EN_LEN;

	cipher_affine((unsigned char *)argv[0], datalen,
			a, b,
			alphabet_en, ALPHABET_EN_LEN, result);
	printf("%s\n", result);
}

static void affine_analyze(int argc, char **argv)
{
	size_t i, datalen;
	int a, b;
	char *plain;
	double freqmap[FREQMAP_LEN];
	datalen = strlen(argv[0]);
	plain = alloca(datalen+1);
	plain[datalen] = 0;
	for(i=0; i<ALPHABET_EN_PRIME_LEN; ++i) {
		double score;
		a = alphabet_en_primes[i];
		for(b=0; b<ALPHABET_EN_LEN; ++b) {
			cipher_affine((unsigned char *)argv[0], datalen,
				a, b,
				alphabet_en, ALPHABET_EN_LEN, (unsigned char *)plain);
			freqmap_calc((unsigned char *)plain, datalen, freqmap);
			score = freqmap_comp(freqmap, freqmap_en);
			if(score > 0.05) {
				printf("Possible a,b = %d, %d, score: %lf, plaintext: %s\n", a, b, score, plain);
			}
		}
	}
}











