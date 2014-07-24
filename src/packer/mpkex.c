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

#include <stdio.h>
#include <string.h>
#include <argp.h>
#include <unistd.h>
#include <fcntl.h>
#include "midgetpack.h"
#include "shared.h"
#include "sha256.h"
#include "aes.h"

const char *argp_program_version = "midgetpack key exchange 0.1 (c) Aris Adamantiadis";
const char args_doc[] = "keyfile";
const char doc[] ="Midgetpack key exchange)";

/* understood options */
static struct argp_option options[]={
	{NULL, 0, NULL, 0, NULL, 0}
};

struct config {
	char *keyfile;
} config = {
	.keyfile=NULL,
};

static error_t parse_opt (int key, char *arg, struct argp_state *state) {
	switch(key){
	case ARGP_KEY_ARG:
		config.keyfile = arg;
		break;
	case ARGP_KEY_END:
		if (state->arg_num < 1) {
			/* Not enough arguments. */
			argp_usage (state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};
struct key_file keyfile;

int main(int argc, char **argv) {
	int r;
	int fd;
	char buffer[128];
	struct curve25519_request req;
	struct curve25519_reply reply;
	uint8_t authentication[SHA256_DIGEST_LEN];
	uint8_t shared_secret[CURVE25519_KEY_LEN];
	uint8_t private[CURVE25519_KEY_LEN];
	HMAC_SHA256_CTX ctx;
	AES_CTX aes;
	char *ptr;

	argp_parse (&argp, argc, argv, 0, 0, NULL);
	fd=open(config.keyfile, O_RDONLY);
	if (fd < 0){
		printf("Cannot open file %s\n",config.keyfile);
		return 1;
	}
	r = read(fd, &keyfile, sizeof(keyfile));
	if (r != sizeof(keyfile)){
		printf("Cannot read keyfile (file too short ?)\n");
		return 1;
	}
	close(fd);
	if ((keyfile.magic[0] != KEY_FILE_MAGIC_0) ||
			(keyfile.magic[1] != KEY_FILE_MAGIC_1) ||
			(keyfile.magic[2] != KEY_FILE_MAGIC_2) ||
			(keyfile.magic[3] != KEY_FILE_MAGIC_3)) {
		printf("Wrong magic\n");
		return 1;
	}
	printf("Waiting for challenge...\n");
	r = read(0, buffer, sizeof(buffer));
	ptr=strchr(buffer,'\n');
	if(ptr != NULL)
		*ptr = '\0';
	ptr=strchr(buffer,'\r');
	if(ptr != NULL)
		*ptr = '\0';
	b64_decode((uint8_t *)&req, sizeof(req), buffer, strlen(buffer));
	HMAC_SHA256_Init(&ctx, keyfile.authentication_key,
			sizeof(keyfile.authentication_key));
	HMAC_SHA256_Update(&ctx, req.pubkey, sizeof(req.pubkey));
	HMAC_SHA256_Final(authentication, &ctx);
	if(memcmp(authentication, req.authentication, sizeof(req.authentication)) != 0){
		printf("MAC authentication error\n");
#ifdef CRYPTO_DEBUG
		print_key("authentication key", keyfile.authentication_key, sizeof(keyfile.authentication_key));
		print_key("pubkey", req.pubkey, sizeof(req.pubkey));
		print_key("expected", req.authentication, sizeof(req.authentication));
		print_key("calculated", authentication, 16);
#endif
		return 1;
	}
	get_random(private, sizeof(private));
	crypto_scalarmult_base(reply.pubkey, private);
	crypto_scalarmult(shared_secret, private, req.pubkey);
	AES_set_key(&aes, &shared_secret[0], &shared_secret[16], AES_MODE_128);
	AES_cbc_encrypt(&aes, keyfile.master_key, reply.encrypted_master, AES_BLOCKSIZE);

#ifdef CRYPTO_DEBUG
	print_key("shared secret", shared_secret, sizeof(shared_secret));
	print_key("master key", keyfile.master_key, sizeof(keyfile.master_key));
	print_key("encrypted master key", reply.encrypted_master,
			sizeof(reply.encrypted_master));
#endif

	HMAC_SHA256_Init(&ctx, keyfile.authentication_key,
			sizeof(keyfile.authentication_key));
	HMAC_SHA256_Update(&ctx, shared_secret, CURVE25519_KEY_LEN);
	HMAC_SHA256_Update(&ctx, reply.encrypted_master, AES128_KEY_LEN);
	HMAC_SHA256_Final(authentication, &ctx);
	memcpy(reply.authentication, authentication, sizeof(reply.authentication));
	b64_encode(buffer,sizeof(buffer),(uint8_t *)&reply, sizeof(reply));
	printf("Response:\n%s\n",buffer);
	return 0;
}
