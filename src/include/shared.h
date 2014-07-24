/*
 * Copyright 2014 Aris Adamantiadis <aris@badcode.be>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef SHARED_H_
#define SHARED_H_

#include "config.h"
#include <stdint.h>
#include <sys/types.h>

#ifndef SHA256_DIGEST_LEN
#define SHA256_DIGEST_LEN 32
#endif

#define AES128_KEY_LEN 16

#define ZERO(x) memset_s((&x),'\0', sizeof(x));

/* common data structures */
#define MAGIC 0xf00dbea7
enum pack_type {
	PACK_TYPE_PASSWORD = 1,
	PACK_TYPE_CURVE25519 = 2
};

enum os_e {
  OS_LINUX = 1,
  OS_FREEBSD,
  OS_UNSUPPORTED,
  OS_INVALID
};

#define STUB_DATA(BITS) \
	struct stub_data_ ## BITS {\
		uint32_t magic;\
		uint ## BITS ## _t data_base;\
		uint32_t data_len;\
		uint ## BITS ## _t banner_addr;\
		uint32_t banner_len;\
		enum pack_type type;\
		uint8_t checksum[32];\
		uint8_t password_salt[8];\
		uint32_t hash_loops; \
		uint8_t encryption_salt[8];\
		/* symmetric HMAC key for authentication of curve25519\
		 * exchange parameters */\
		uint8_t authentication_key[16];\
	} //__attribute__((packed))
STUB_DATA(32);
STUB_DATA(64);

void memset_s(void *v, int c, size_t n);

void compute_session_keys(uint8_t encryptkey[AES128_KEY_LEN],
		uint8_t IV[AES128_KEY_LEN],
		uint8_t integrity[AES128_KEY_LEN],
		uint8_t master_key[AES128_KEY_LEN],
		uint8_t encryption_salt[8]);

void compute_session_keys_password (char *password, int iterations,
		uint8_t encryptkey[16],
		uint8_t IV[16],
		uint8_t integrity[16],
		uint8_t encryption_salt[8],
		uint8_t password_salt[8]
		);
void compute_checksum(void *payload, size_t len, uint8_t integrity[SHA256_DIGEST_LEN],
		uint8_t checksum[SHA256_DIGEST_LEN]);
void b64_encode(char *dest, size_t dest_size, uint8_t *input, size_t input_size);
int b64_decode(uint8_t *dest, size_t dest_size, char *input, size_t input_size);

/* curve25519_ref.c */
#define CURVE25519_KEY_LEN 32

/* q = p**n */
int crypto_scalarmult(unsigned char q[CURVE25519_KEY_LEN],
  const unsigned char n[CURVE25519_KEY_LEN],
  const unsigned char p[CURVE25519_KEY_LEN]);
/* q = base**n */
int crypto_scalarmult_base(unsigned char q[CURVE25519_KEY_LEN],
  const unsigned char n[CURVE25519_KEY_LEN]);

struct curve25519_request{
	uint8_t pubkey[CURVE25519_KEY_LEN];
	uint8_t authentication[16];
};

struct curve25519_reply{
	uint8_t pubkey[CURVE25519_KEY_LEN];
	uint8_t encrypted_master[AES128_KEY_LEN];
	uint8_t authentication[16];
};

/* this function is defined differently in packer and stub */
int get_random(uint8_t *dest, size_t len);
void print_key(const char *name, uint8_t *key, int len);

#endif /* SHARED_H_ */
