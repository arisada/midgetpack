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

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "midgetpack.h"
#include "sha256.h"
#include "aes.h"

int get_random(uint8_t *dest, size_t len){
	int fd;
	int rc;
	fd=open("/dev/urandom",O_RDONLY);
	if (fd < 0){
		perror("Opening /dev/urandom");
	}
	rc = read(fd, dest, len);
	close(fd);
	if(rc != (int)len)
		return -1;
	else
		return 0;
}

char *ask_password(void){
	char *p1, *p2;
	char *p;
	p=getpass("Please enter password:");
	p1=strdup(p);
	memset_s(p,0,strlen(p));

	p=getpass("Enter the password again:");
	p2=strdup(p);
	memset_s(p,0,strlen(p));

	if (strcmp(p1,p2)!= 0){
		printf("Passwords do not match\n");
		memset_s(p2,0,strlen(p2));
		memset_s(p1,0,strlen(p1));
		free(p2);
		free(p1);
		return NULL;
	}

	memset_s(p2,0,strlen(p2));
	free(p2);
	return p1;
}

#ifdef CRYPTO_DEBUG
void print_key(const char *name, uint8_t *key, int len){
	int i;
	uint32_t *v=(uint32_t *)key;
	printf("key %s: ",name);
	for (i=0;i<len/4;++i){
		printf("%x ", v[i]);
	}
	printf("\n");
}
#endif

void encrypt_payload(void *payload, size_t len, uint8_t encryptkey[16], uint8_t IV[16]){
	AES_CTX ctx;
	AES_set_key(&ctx, encryptkey, IV, AES_MODE_128);
#ifdef CRYPTO_DEBUG
	printf("Aes_encrypt (%x %d) = ", *(uint32_t *)payload, (int)len);
#endif
	/* do the encryption in-place to spare memory */
	AES_cbc_encrypt(&ctx, payload, payload, len);
#ifdef CRYPTO_DEBUG
	printf("%x\n", *(uint32_t *)payload);
#endif
}

int generate_password_parameters(uint8_t encryption_salt[8], uint8_t password_salt[8]){
	int rc;
	rc = get_random(encryption_salt, 8);
	rc |= get_random(password_salt, 8);
	if (rc != 0){
		printf("Error getting entropy\n");
		return -1;
	}
	return 0;
}

int generate_curve25519_parameters(uint8_t encryption_salt[8],
		uint8_t master_key[AES128_KEY_LEN],
		uint8_t authentication_key[AES128_KEY_LEN]){
	int rc;
	rc = get_random(encryption_salt, 8);
	rc |= get_random(master_key, AES128_KEY_LEN);
	rc |= get_random(authentication_key, AES128_KEY_LEN);
	if (rc != 0){
		printf("Error getting entropy\n");
		return -1;
	}
	return 0;
}
