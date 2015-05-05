#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "../rypto.h"

static void substitution_encrypt(int argc, char **argv);
static void substitution_decrypt(int argc, char **argv);

struct command *construct_substitution_cmd()
{
	struct command *substitution, *cmd;
	substitution = malloc(sizeof(struct command));
	strcpy(substitution->cmd, "substi");
	cmd = malloc(sizeof(struct command));
	substitution->child = cmd;
	substitution->next = 0;
	strcpy(cmd->cmd, "encrypt");
	cmd->argcnt = 2;
	cmd->perform = substitution_encrypt;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "decrypt");
	cmd->argcnt = 2;
	cmd->perform = substitution_decrypt;
	cmd->child = 0;
	cmd->next = 0;
	return substitution;
}

static void substitution_encrypt(int argc, char **argv)
{
	unsigned char *result;
	size_t datalen;
	datalen = strlen(argv[0]);
	result = alloca(datalen+1);
	result[datalen] = 0;
	if(strlen(argv[1]) != ALPHABET_EN_LEN) {
		printf("Substituon alphabet corrupt!");
		exit(-1);
	}
	cipher_substitution((unsigned char *)argv[0], datalen,
			alphabet_en, (unsigned char *)argv[1], ALPHABET_EN_LEN, result);
	printf("%s\n", result);
}


static void substitution_decrypt(int argc, char **argv)
{
	unsigned char *result;
	size_t datalen;
	datalen = strlen(argv[0]);
	result = alloca(datalen+1);
	result[datalen] = 0;
	if(strlen(argv[1]) != ALPHABET_EN_LEN) {
		printf("Substituon alphabet corrupt!");
		exit(-1);
	}
	cipher_substitution((unsigned char *)argv[0], datalen,
			(unsigned char *)argv[1], alphabet_en, ALPHABET_EN_LEN, result);
	printf("%s\n", result);
}
struct substi_state_alpha {
	char alpha[ALPHABET_EN_LEN+1];
	struct substi_state_alpha *next;
	double score;
	int round;
};
struct freq_byte_pair {
	double freq;
	char letter;
};

int fbp_comp(const void *lhs, const void *rhs)
{
	struct freq_byte_pair *l = (struct freq_byte_pair *)lhs;
	struct freq_byte_pair *r = (struct freq_byte_pair *)rhs;
	return (l->freq > r->freq);
}

