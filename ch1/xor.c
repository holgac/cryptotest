#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "../rypto.h"

static void xor_encrypt(int argc, char **argv);
static void xor_rawencrypt(int argc, char **argv);
static void xor_analyze(int argc, char **argv);
static void xor_analyzefile(int argc, char **argv);
static void xor_detectinfile(int argc, char **argv);

struct command *construct_xor_cmd()
{
	struct command *xor, *cmd;
	xor = malloc(sizeof(struct command));
	strcpy(xor->cmd, "xor");
	cmd = malloc(sizeof(struct command));
	xor->child = cmd;
	xor->next = 0;
	strcpy(cmd->cmd, "encrypt");
	cmd->argcnt = 2;
	cmd->perform = xor_encrypt;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "rawencrypt");
	cmd->argcnt = 2;
	cmd->perform = xor_rawencrypt;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "decrypt");
	cmd->argcnt = 2;
	cmd->perform = xor_encrypt;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "analyzefile");
	cmd->argcnt = 1;
	cmd->perform = xor_analyzefile;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "analyze");
	cmd->argcnt = 1;
	cmd->perform = xor_analyze;
	cmd->child = 0;
	cmd->next = malloc(sizeof(struct command));
	cmd = cmd->next;
	strcpy(cmd->cmd, "detectinfile");
	cmd->argcnt = 1;
	cmd->perform = xor_detectinfile;
	cmd->child = 0;
	cmd->next = 0;
	return xor;
}

static void xor_rawencrypt(int argc, char **argv)
{
	size_t datalen, keylen;
	unsigned char *result;
	char *res_hex;
	datalen = strlen(argv[0]);
	keylen = strlen(argv[1]);
	result = alloca(datalen);
	cipher_xor((unsigned char *)argv[0], datalen, (unsigned char *)argv[1], keylen, result);
	res_hex = alloca(datalen*2 + 1);
	to_hex(result, datalen, res_hex);
	res_hex[datalen*2] = 0;
	printf("%s\n", res_hex);
}

static void xor_encrypt(int argc, char **argv)
{
	unsigned char *data, *key;
	size_t datalen, keylen;
	unsigned char *result;
	char *result_hex;
	datalen = strlen(argv[0])/2;
	keylen = strlen(argv[1])/2;
	key = alloca(keylen);
	data = alloca(datalen);
	result = alloca(datalen);
	result_hex = alloca(datalen*2 + 1);
	from_hex(argv[0], datalen*2, data);
	from_hex(argv[1], keylen*2, key);
	cipher_xor(data, datalen, key, keylen, result);
	to_hex(result, datalen, result_hex);
	result_hex[datalen*2] = 0;
	printf("%s\n", result_hex);
}
struct xor_keystat {
	size_t keylen;
	double edit;
	double score;
};
static int xor_keystat_cmp(const void *lhs, const void *rhs)
{
	struct xor_keystat *l = (struct xor_keystat *)lhs;
	struct xor_keystat *r = (struct xor_keystat *)rhs;
	if(l->score > r->score)
		return -1;
	return 1;
}

static void xor_analyzefile(int argc, char **argv)
{
	int fd;
	struct stat filestat;
	char *base64, *plain;
	size_t datalen, i, keylen, j;
	unsigned char *data;
	double kasiski_stats[41];
	struct xor_keystat keystats[41];
	double freqmap[FREQMAP_LEN];
	fd = open(argv[0], O_RDONLY);
	fstat(fd, &filestat);
	base64 = alloca(filestat.st_size);
	datalen = read(fd, base64, filestat.st_size);
	data = alloca(3 * datalen / 4);
	from_base64(base64, datalen-1, data);
	datalen = 3 * datalen / 4;
	plain = alloca(datalen+1);
	plain[datalen] = 0;
	kasiski_calc(data, datalen, kasiski_stats, 41);
	for(keylen=2; keylen<41; ++keylen) {
		size_t dist=0;
		for(i=0; i<20; ++i)
			dist += edit_dist(data+i*keylen, data+(i+20)*keylen, keylen);
		keystats[keylen].keylen = keylen;
		keystats[keylen].edit = dist * 0.05 / keylen;
		if(kasiski_stats[keylen] < 0.00001)
			keystats[keylen].score = 0;
		else
			keystats[keylen].score = 1.0 / keystats[keylen].edit; // / kasiski_stats[keylen];
	}
	qsort(keystats+2, 39, sizeof(struct xor_keystat), xor_keystat_cmp);
	for(i=2; i<41; ++i) {
		unsigned char possible_keys[41][256];
		unsigned char key_cnts[41];
		size_t keyidx, keycnt;
		int broken = 0;
		keylen = keystats[i].keylen;
		printf("Trying %ld edit dist %lf kasiski %lf score: %lf\n", keylen, keystats[i].edit, kasiski_stats[keylen], keystats[i].score);
		for(keyidx=0; keyidx<keylen && !broken; ++keyidx) {
			double best_score = 0;
			unsigned char best_k;
			key_cnts[keyidx] = 0;
			for(j=0; j<256; ++j) {
				double score;
				freqmap_pcalc_xor(data+keyidx, datalen, j, keylen, freqmap);
				score = freqmap_comp(freqmap, freqmap_en);
				if(score > 0.05) {
					possible_keys[keyidx][key_cnts[keyidx]] = j;
					key_cnts[keyidx] += 1;
				}
				if(score > best_score) {
					best_score = score;
					best_k = j;
				}
			}
			if(best_score < 0.05) {
				broken = 1;
				// key_cnts[keyidx] = 1;
				// possible_keys[keyidx][0] = best_k;
				// printf("Selected %c at %ld score %lf\n", (char)best_k, keyidx, best_score);
			}
		}
		keycnt = 0;
		keyidx = 0;
		if(!broken) {
			keycnt = 1;
			for(keyidx=0; keyidx<keylen; ++keyidx) {
				keycnt *= key_cnts[keyidx];
			}
		}
		while(keyidx < keycnt) {
			unsigned char key[41];
			double score;
			size_t total_pos=1;
			for(j=0; j<keylen; ++j) {
				size_t curidx;
				curidx = (keyidx/total_pos) % key_cnts[j];
				total_pos *= key_cnts[j];
				key[j] = possible_keys[j][curidx];
			}
			key[keylen] = 0;
			cipher_xor(data, 80, key, keylen, (unsigned char *)plain);
			freqmap_calc((unsigned char *)plain, 80, freqmap);
			plain[80] = 0;
			score = freqmap_comp(freqmap, freqmap_en);
			printf("\tPossible key: %s score %lf, plaintext sample: \n\t%s\n", (char *)key, score, plain);
			keyidx++;
		}
	}
}

static void xor_analyze(int argc, char **argv)
{
	size_t datalen, j;
	unsigned char *data, *result;
	double freqmap[FREQMAP_LEN];
	datalen = strlen(argv[0])/2;
	data = alloca(datalen);
	result = alloca(datalen+1);
	from_hex(argv[0], datalen*2, data);
	for(j=0; j<256; ++j) {
		double score;
		freqmap_pcalc_xor(data, datalen, j, 1, freqmap);
		score = freqmap_comp(freqmap, freqmap_en);
		if(score > 0.05) {
			unsigned char key[1];
			key[0] = j;
			cipher_xor(data, datalen, key, 1, result);
			result[datalen] = 0;
			printf("Possible key %lu, plaintext: %s\n", j, (char *)result);
		}
	}
}

static void xor_detectinfile(int argc, char **argv)
{
	FILE *f;
	size_t i, datalen;
	double freqmap[FREQMAP_LEN];
	f = fopen(argv[0], "r");
	while(!feof(f)) {
		unsigned char key[1];
		char buf[128];
		unsigned char data[64];
		unsigned char result[64];
		fgets(buf, 128, f);
		datalen = strlen(buf)/2;
		from_hex(buf, datalen*2, data);
		for(i=0; i<256; ++i) {
			double score;
			key[0] = i;
			freqmap_pcalc_xor(data, datalen, key[0], 1, freqmap);
			score = freqmap_comp(freqmap, freqmap_en);
			if(score > 0.05) {
				cipher_xor(data, datalen, key, 1, result);
				printf("Possible ciphertext %s, key %lu, plaintext: %s\n", buf, i, (char *)result);
			}
		}
	}
}




