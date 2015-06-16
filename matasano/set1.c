#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "../rypto.h"
#include "../impl/util.h"

static void h2b(int argc, char **argv);
static void b2h(int argc, char **argv);
static void b2b(int argc, char **argv);
static void b2d(int argc, char **argv);
static void pad(int argc, char **argv);
static void mtgen(int argc, char **argv);
static void mtseed(int argc, char **argv);
static void mtclone(int argc, char **argv);
static void mtcip(int argc, char **argv);
static void mtgenpass(int argc, char **argv);
static void mtchkpass(int argc, char **argv);

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
	strcpy(cmd->cmd, "mtchkpass");
	cmd->argcnt = 1;
	cmd->perform = mtchkpass;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "mtgenpass");
	cmd->argcnt = 0;
	cmd->perform = mtgenpass;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "mtcip");
	cmd->argcnt = 0;
	cmd->perform = mtcip;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "mtclone");
	cmd->argcnt = 0;
	cmd->perform = mtclone;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "mtseed");
	cmd->argcnt = 0;
	cmd->perform = mtseed;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "mtgen");
	cmd->argcnt = 2;
	cmd->perform = mtgen;
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

static void mtgen(int argc, char **argv)
{
	u32 seed, val, val2;
	size_t cnt, i;
	struct mt19937 mt;
	struct mt19937_cached cmt;
	seed = atol(argv[0]);
	cnt = atoi(argv[1]);
	mt19937_init(&mt, seed);
	mt19937c_init(&cmt, seed);
	for(i=0; i<cnt; ++i) {
		val = mt19937_gen(&mt);
		printf("%u ", val);
		mt19937c_fill(&cmt, &val2, sizeof(u32));
		if(val != val2)
			printf("val != val2: %x != %x\n", val, val2);
	}
	printf("\n");
}

static u32 mtrgen(struct timeval* tv)
{
	struct mt19937 mt;
	u32 v;
	gettimeofday(tv, NULL);
	/* actually  usec is in range 0-1M, but good enough for us now */
	mt19937_init(&mt, (u32)tv->tv_usec);
	usleep(50000 + rand()%500000);
	v = mt19937_gen(&mt);
	return v;
}
static u32 mt1(u32 seed)
{
	return 1 + 0x6c078965 * (seed ^ (seed>>30));
}
static u32 mt397(u32 seed)
{
	size_t i;
	u32 p = seed;
	for(i=0; i<397; ++i) {
		p = i + 1 + 0x6c078965* (p ^ (p>>30));
	}
	return p;
}

static u32 mtr0(u32 seed)
{
	u32 mts0 = seed, mts1=mt1(seed), mts397=mt397(seed);
	u32 y = (mts0&0x80000000) + (mts1&0x7fffffff);
	y = mts397 ^ (y>>1) ^ (y%2)*0x9908b0df;
	y ^= (y<<7) & 0x9d2c5680;
	y ^= (y<<15) & 0xefc60000;
	y ^= y >> 18;
	return y;
}

static void mtseed(int argc, char **argv)
{
	u32 genval, seed, gseed;
	size_t i;
	struct timeval tv;
	for(i=0; i<1; ++i) {
		genval = mtrgen(&tv);
		seed = tv.tv_usec;
		gettimeofday(&tv, NULL);
		gseed = (u32)tv.tv_usec;
		while(mtr0(gseed) != genval) {
			if(gseed == 0)
				gseed = 1000001;
			gseed--;
		}
		if(gseed == seed)
			printf("Correct guess\n");
		else
			printf("Wrong guess!\n");
	}
}

static u32 untamper(u32 y)
{
	y ^= y >> 18;
	y ^= (y<<15) & 0xefc60000;
	y ^= ((y & 0xf)<<7) & 0x9d2c5680;
	y ^= ((y & 0x7f0)<<7) & 0x9d2c5680;
	y ^= ((y & 0x3f800)<<7) & 0x9d2c5680;
	y ^= ((y & 0x1fc0000)<<7) & 0x9d2c5680;
	return y;
}

static void mtclone(int argc, char **argv)
{
	struct mt19937 mt, cmt;
	u32 *vals;
	size_t i;
	vals = malloc(sizeof(u32) * 624);
	mt19937_init(&mt, time(NULL));
	for(i=0; i<624; ++i) {
		vals[i] = mt19937_gen(&mt);
		cmt.state[i] = untamper(vals[i]);
	}
	cmt.idx = 1;
	for(i=1; i<624; ++i) {
		if(mt19937_gen(&cmt) != vals[i]) {
			printf("copy failure: %lu!\n", i);
			exit(-1);
		}
	}
	for(i=0; i<624; ++i) {
		if(mt19937_gen(&mt) != mt19937_gen(&cmt)) {
			printf("next-batch error: %lu\n", i);
			exit(-1);
		}
	}
	printf("Copy success!\n");
	free(vals);
}

static void mtcip(int argc, char **argv)
{
	struct mt19937_cached *mt;
	u16 seed;
	size_t i, randlen, datalen;
	u8 data[64], res[14];
	seed = rand();
	randlen = 10+rand()%32;
	datalen = randlen + 14;
	fill_random(data, randlen);
	memset(data+randlen, 'A', 14);
	mt = malloc(sizeof(*mt));
	mt19937c_init(mt, seed);
	mt19937c_xor(mt, data, datalen);
	memset(res, 'A', 14);
	xor_arr(res, data+randlen, 14);

	for(i=0; i<0x10000; ++i) {
		mt19937c_init(mt, i);
		mt19937c_fill(mt, data, datalen);
		if(memcmp(data+randlen, res, 14) == 0) {
			printf("Found!\n");
			if(i != seed) {
				printf("Mistaken!\n");
			}
			break;
		}
	}
	free(mt);
}

static void mtgenpass(int argc, char **argv)
{
	struct timeval tv;
	struct mt19937_cached *mt;
	u8 randdata[32];
	char base64[64];
	mt = malloc(sizeof(*mt));
	gettimeofday(&tv, NULL);
	mt19937c_init(mt, tv.tv_sec);
	mt19937c_fill(mt, randdata, 32);
	to_base64(randdata, 32, base64, NULL);
	printf("%s\n", base64);
	free(mt);
}

static void mtchkpass(int argc, char **argv)
{
	struct timeval tv;
	struct mt19937_cached *mt;
	size_t len, i;
	u8 rawdata[64];
	u8 chkdata[64];

	mt = malloc(sizeof(*mt));
	gettimeofday(&tv, NULL);
	from_base64(argv[0], strlen(argv[0]), rawdata, &len);
	for(i=0; i<(60*60*24); ++i) {
		mt19937c_init(mt, tv.tv_sec-i);
		mt19937c_fill(mt, chkdata, len);
		if(memcmp(chkdata, rawdata, len) == 0) {
			printf("Generated %lu seconds (%lu min) ago!\n", i, i/60);
			break;
		}
	}
	if(i == (60*60*24)) {
		printf("Not generated today!\n");
	}
	free(mt);
}











