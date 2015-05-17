#ifndef AES_H_
#define AES_H_

#include "../rypto.h"
#define AES_BIT_128 0
#define AES_OPMOD_ECB 0
#define AES_OPMOD_CBC 1

/**
 * struct aes_opmod - AES operation context
 * @bs: block size in bytes
 * @padop: pad operation (can be NULL)
 * @init: called on creation with key and IV (if any) args
 * @enc: block encrypt cb
 * @dec: block decrypt cb
 * @context: optional opmod data
 */
struct aes_opmod {
	size_t bs;
	size_t (*padop)(unsigned char *data, size_t datalen, size_t blocklen);
	void (*init)(struct aes_opmod *opmod, const unsigned char *key,
			const unsigned char *iv);
	void (*enc)(struct aes_opmod *opmod, unsigned char *data);
	void (*dec)(struct aes_opmod *opmod, unsigned char *data);
	unsigned char context[0];
};

struct aes_opmod *aes_create_opmod(int bit, int opmod);
void aes_enc(struct aes_opmod *opmod, const unsigned char *plain, size_t len,
		unsigned char *cipher, const unsigned char *key, const unsigned char *iv);
void aes_dec(struct aes_opmod *opmod, const unsigned char *cipher, size_t len,
		unsigned char *plain, const unsigned char *key, const unsigned char *iv);


#endif
