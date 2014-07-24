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

#include <string.h>
#include <stdio.h>
#include "shared.h"
#include "sha256.h"

void memset_s(void *v, int c, size_t n) {
	volatile uint8_t *p = v;
	while (n--)
		*p++ = c;
}

void compute_session_keys(uint8_t encryptkey[AES128_KEY_LEN],
		uint8_t IV[AES128_KEY_LEN],
		uint8_t integrity[AES128_KEY_LEN],
		uint8_t master_key[AES128_KEY_LEN],
		uint8_t encryption_salt[8]){

	uint8_t long_encryptkey[SHA256_DIGEST_LEN];
	uint8_t	long_IV[SHA256_DIGEST_LEN];
	uint8_t long_integrity[SHA256_DIGEST_LEN];

	HMAC_SHA256_CTX ctx;

	HMAC_SHA256_Init(&ctx, master_key, AES128_KEY_LEN);
	HMAC_SHA256_Update(&ctx,encryption_salt, 8);
	HMAC_SHA256_Update(&ctx, "encryption", 10);
	HMAC_SHA256_Final(long_encryptkey, &ctx);

	HMAC_SHA256_Init(&ctx, master_key, AES128_KEY_LEN);
	HMAC_SHA256_Update(&ctx,encryption_salt, 8);
	HMAC_SHA256_Update(&ctx, "IV", 2);
	HMAC_SHA256_Final(long_IV, &ctx);

	HMAC_SHA256_Init(&ctx, master_key, AES128_KEY_LEN);
	HMAC_SHA256_Update(&ctx,encryption_salt, 8);
	HMAC_SHA256_Update(&ctx, "integrity", 9);
	HMAC_SHA256_Final(long_integrity, &ctx);

	memcpy(encryptkey, long_encryptkey, AES128_KEY_LEN);
	memcpy(IV, long_IV, AES128_KEY_LEN);
	memcpy(integrity, long_integrity, AES128_KEY_LEN);
	ZERO(long_encryptkey);
	ZERO(long_IV);
	ZERO(long_integrity);
	ZERO(ctx);
}

void compute_session_keys_password (char *password, int iterations,
		uint8_t encryptkey[16],
		uint8_t IV[16],
		uint8_t integrity[16],
		uint8_t encryption_salt[8],
		uint8_t password_salt[8]
		){

	uint8_t master_key[AES128_KEY_LEN];
	/* compute the password hash */
	PBKDF2_SHA256((uint8_t *)password, strlen(password), password_salt, 8, iterations,
			master_key, sizeof(master_key));
#ifdef CRYPTO_DEBUG
	print_key("masterkey", master_key, sizeof(master_key));
#endif
	compute_session_keys(encryptkey, IV, integrity, master_key, encryption_salt);
	ZERO(master_key);
}

void compute_checksum(void *payload, size_t len, uint8_t integrity[AES128_KEY_LEN],
		uint8_t checksum[SHA256_DIGEST_LEN]){
	HMAC_SHA256_CTX ctx;
	HMAC_SHA256_Init(&ctx, integrity, AES128_KEY_LEN);
	HMAC_SHA256_Update(&ctx, payload, len);
	HMAC_SHA256_Final(checksum, &ctx);
}

char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz-_";
/* This is not a real base 64. I don't care, it's not the purpose */
void b64_encode(char *dest, size_t dest_size, uint8_t *input, size_t input_size){
	size_t i,j,o;
	uint32_t value;
	uint8_t offset;
	o=0;
	for (i=0;i<input_size;i+=3){
		switch(input_size - i){
		case 1:
			value = input[i];
			break;
		case 2:
			value = input[i] + (input[i+1] << 8);
			break;
		default:
			value = input[i] + (input[i+1] << 8) + (input[i+2] << 16);
		}
		for (j=0;j<4;++j){
			offset = value & 0x3f;
			value >>= 6;
			dest[o++] = alphabet[offset];
			if(o >= dest_size){
				dest[o-1]='\0';
				return;
			}
		}
	}
	dest[o]='\0';
}

int b64_decode(uint8_t *dest, size_t dest_size, char *input, size_t input_size){
	size_t i,j, o;
	uint32_t value;
	char *ptr;
	int rc = 0;

	o=0;
	/* not interested in partial chunks */
	input_size -= input_size % 4;
	if ((input_size / 4) *3 > dest_size)
		rc = -1;
	for (i=0;i<input_size;i+=4){
		value = 0;
		/* the decoding is opposite endian from encoding */
		for(j=4;j>0; --j){
			value <<=6;
			ptr = strchr(alphabet, input[i+j-1]);
			if(ptr == NULL)
				return -1;
			value |= (ptr-alphabet);
		}
		for(j=0;j<3 && o<dest_size; ++j){
			dest[o++]=value & 0xff;
			value >>=8;
		}
	}
	return rc;
}
