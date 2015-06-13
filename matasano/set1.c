#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "../rypto.h"
#include "../impl/util.h"

static void h2b(int argc, char **argv);
static void b2h(int argc, char **argv);
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
	strcpy(cmd->cmd, "b2h");
	cmd->argcnt = 1;
	cmd->perform = b2h;
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
	int r;
	hexlen = strlen(argv[0]);
	data = alloca(hexlen/2 + 1);
	from_hex(argv[0], hexlen, data);
	base64 = alloca(2*hexlen/3 + 1);
	r = to_base64(data, hexlen/2, base64, NULL);
	if(r)
		printf("ERROR");
	printf("%s\n", base64);
}

static void b2h(int argc, char **argv)
{
	unsigned char *data;
	size_t len;
	char *hex;
	len = strlen(argv[0]);
	data = alloca(len);
	from_base64(argv[0], len, data, &len);
	hex = alloca(len*2);
	to_hex(data, len, hex);
	printf("%s\n", hex);
}


static void b2b(int argc, char **argv)
{
	size_t base64len, rawlen;
	unsigned char *data;
	char *base64;
	base64len = strlen(argv[0]);
	data = alloca(3*base64len/4 + 1);
	from_base64(argv[0], base64len, data, &rawlen);
	base64 = alloca(base64len);
	to_base64(data, rawlen, base64, NULL);
	printf("%s\n", base64);
}

static void b2d(int argc, char **argv)
{
	size_t base64len;
	unsigned char *data;
	base64len = strlen(argv[0]);
	data = alloca(3*base64len/4 + 1);
	from_base64(argv[0], base64len, data, NULL);
	data[3*base64len/4] = 0;
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



