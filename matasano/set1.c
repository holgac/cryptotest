#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "../rypto.h"

static void h2b(int argc, char **argv);
static void b2b(int argc, char **argv);
static void b2d(int argc, char **argv);
static void pad(int argc, char **argv);
struct command *construct_matasano_cmd()
{
	struct command *mst, *cmd;
	mst = malloc(sizeof(struct command));
	strcpy(mst->cmd, "mst");
	cmd = malloc(sizeof(struct command));
	mst->child = cmd;
	mst->next = 0;
	strcpy(cmd->cmd, "h2b");
	cmd->argcnt = 1;
	cmd->perform = h2b;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "b2b");
	cmd->argcnt = 1;
	cmd->perform = b2b;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "b2d");
	cmd->argcnt = 1;
	cmd->perform = b2d;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "pad");
	cmd->argcnt = 0;
	cmd->perform = pad;
	cmd->child = 0;
	cmd->next = 0;
	return mst;
}
/*
 * this is actually challenge 1
 */
static void h2b(int argc, char **argv)
{
	size_t hexlen;
	unsigned char *data;
	char *base64;
	hexlen = strlen(argv[0]);
	data = alloca(hexlen/2 + 1);
	from_hex(argv[0], hexlen, data);
	base64 = alloca(2*hexlen/3 + 1);
	base64[2*hexlen/3] = 0;
	to_base64(data, hexlen/2, base64);
	printf("%s\n", base64);
}

static void b2b(int argc, char **argv)
{
	size_t base64len;
	unsigned char *data;
	char *base64;
	base64len = strlen(argv[0]);
	data = alloca(3*base64len/4 + 1);
	from_base64(argv[0], base64len, data);
	base64 = alloca(base64len + 1);
	base64[base64len] = 0;
	to_base64(data, 3*base64len/4, base64);
	printf("%s\n", base64);
}

static void b2d(int argc, char **argv)
{
	size_t base64len, i;
	unsigned char *data;
	base64len = strlen(argv[0]);
	data = alloca(3*base64len/4 + 1);
	from_base64(argv[0], base64len, data);
	data[3*base64len/4] = 0;
	for(i=0; i<(3*base64len/4); ++i)
		printf("%0.2x", data[i]);
	printf("\nPlain: %s\n", (char *)data);
}

static void pad(int argc, char **argv)
{
	unsigned char data[32];
	fill_random(data, 24);
	if(pad_pkcs7(data, 24, 16) != 32) {
		printf("Problem in padding\n");
		exit(-1);
	}
	if(unpad_pkcs7(data, 32, 16) != 24) {
		printf("Problem in unpadding\n");
		exit(-1);
	}
	if(pad_pkcs7(data, 25, 16) != 32) {
		printf("Problem in padding\n");
		exit(-1);
	}
	if(unpad_pkcs7(data, 32, 16) != 25) {
		printf("Problem in unpadding\n");
		exit(-1);
	}
	data[28] = 2;
	if(unpad_pkcs7(data, 32, 16) != -1) {
		printf("Problem in unpadding\n");
		exit(-1);
	}
	printf("All good\n");
}



