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
#include <stdlib.h>
#include <fcntl.h>
#include "midgetpack.h"
#include "shared.h"
#include "sha256.h"
#include "aes.h"

const char *argp_program_version = "midgetpack 0.1 (c) Aris Adamantiadis";
const char args_doc[] = "file";
const char doc[] ="Midgetpack: an ELF file packer.\nSupported architectures:\n"
#ifdef HAVE_LINUX_X86
		"  linux/x86\n"
#endif
#ifdef HAVE_LINUX_AMD64
		"  linux/amd64\n"
#endif
#ifdef HAVE_LINUX_ARMV6
		"  linux/armv6\n"
#endif
#ifdef HAVE_FREEBSD_X86
		"  freebsd/x86\n"
#endif
#ifdef HAVE_FREEBSD_AMD64
		"  freebsd/amd64\n"
#endif
		"";

/* understood options */
static struct argp_option options[]={
	{
		.name="usepassword",
		.key='p',
		.arg=NULL,
		.flags=0,
		.doc="Use password encryption (default)",
		.group=1
	}, {
		.name="password",
		.key='P',
		.arg="password",
		.flags=0,
		.doc="Use this password (don't ask)",
		.group=1
	}, {
		.name="iterations",
		.key='i',
		.arg="iterations",
		.flags=0,
		.doc="Hash password with n iterations (default=20000)",
		.group=1
	}, {
		.name="curve25519",
		.key='c',
		.arg=NULL,
		.flags=0,
		.doc="Use curve25519 key exchange",
		.group=2
	}, {
		.name="output",
		.key='o',
		.arg="file",
		.flags=0,
		.doc="Output file [a.out]",
		.group=0
	}, {
		.name="keyfile",
		.key='k',
		.arg="keyfile",
		.flags=0,
		.doc="Output key file [key]",
		.group=2
	},
	{
		.name="banner",
		.key='b',
		.arg="bannerfile",
		.flags=0,
		.doc="Banner to show upon starting",
		.group=0
	},
	{NULL, 0, NULL, 0, NULL, 0}
};

struct config {
	enum pack_type pack_type;
	const char *outfile;
	char *keyfile;
	char *elffile;
	char *bannerfile;
	char *password;
	int loops;
} config = {
	.pack_type=PACK_TYPE_PASSWORD,
	.outfile="a.out",
	.keyfile=NULL,
	.elffile=NULL,
	.bannerfile=NULL,
	.password=NULL,
	.loops=20000
};

static error_t parse_opt (int key, char *arg, struct argp_state *state) {
	switch(key){
	case 'p':
		config.pack_type=PACK_TYPE_PASSWORD;
		break;
	case 'c':
		config.pack_type=PACK_TYPE_CURVE25519;
		break;
	case 'o':
		config.outfile=arg;
		break;
	case 'k':
		config.keyfile=arg;
		break;
	case 'b':
		config.bannerfile=arg;
		break;
	case 'P':
		config.pack_type=PACK_TYPE_PASSWORD;
		config.password = arg;
		break;
	case 'i':
		config.pack_type = PACK_TYPE_PASSWORD;
		config.loops = atoi(arg);
		if (config.loops <= 0){
			printf("iterations parameter must be a positive integer\n");
			return -1;
		}
		break;
	case ARGP_KEY_ARG:
		config.elffile = arg;
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

static int build_packed_file(struct elf_file_s *file);

int main(int argc, char **argv) {
  struct elf_file_s *file;
  argp_parse (&argp, argc, argv, 0, 0, NULL);

  file = elf_file_open(config.elffile);
  if (file == NULL)
    return 1;
  switch (elf_get_arch(file)){
    case ARCH_x86:
      printf("x86 ELF file\n");
      break;
    case ARCH_AMD64:
      printf("amd64 ELF file\n");
      break;
    case ARCH_ARM:
      printf("arm ELF file\n");
      break;
    case ARCH_INVALID:
      printf("Invalid ELF file\n");
      break;
    case ARCH_UNSUPPORTED:
      printf("Unsupported ELF architecture\n");
      break;
  }
  build_packed_file(file);
  elf_file_free(file);
  return 0;
}

#ifdef HAVE_LINUX_X86
extern unsigned char _binary_stub_linux_x86_start[];
extern size_t _binary_stub_linux_x86_size;
#endif

#ifdef HAVE_FREEBSD_X86
extern unsigned char _binary_stub_freebsd_x86_start[];
extern size_t _binary_stub_freebsd_x86_size;
#endif

#ifdef HAVE_LINUX_AMD64
extern unsigned char _binary_stub_linux_amd64_start[];
extern size_t _binary_stub_linux_amd64_size;
#endif

#ifdef HAVE_FREEBSD_AMD64
extern unsigned char _binary_stub_freebsd_amd64_start[];
extern size_t _binary_stub_freebsd_amd64_size;
#endif

#ifdef HAVE_LINUX_ARMV6
extern unsigned char _binary_stub_linux_armv6_start[];
extern size_t _binary_stub_linux_armv6_size;
#endif

enum stubs_enum {
#ifdef HAVE_LINUX_X86
	STUB_LINUX_X86 = 0,
#endif
#ifdef HAVE_FREEBSD_X86
	STUB_FREEBSD_X86,
#endif
#ifdef HAVE_LINUX_AMD64
	STUB_LINUX_AMD64,
#endif
#ifdef HAVE_FREEBSD_AMD64
	STUB_FREEBSD_AMD64,
#endif
#ifdef HAVE_LINUX_ARMV6
	STUB_LINUX_ARMV6,
#endif
	STUB_END
};

struct stub {
	uint8_t *base;
	size_t size;
} stubs[]={
#ifdef HAVE_LINUX_X86
	{
		.base= _binary_stub_linux_x86_start,
		.size=(size_t) &_binary_stub_linux_x86_size
	},
#endif
#ifdef HAVE_FREEBSD_X86
	{
		.base= _binary_stub_freebsd_x86_start,
		.size=(size_t) &_binary_stub_freebsd_x86_size
	},
#endif
#ifdef HAVE_LINUX_AMD64
	{
		.base=_binary_stub_linux_amd64_start,
		.size=(size_t) &_binary_stub_linux_amd64_size
	},
#endif
#ifdef HAVE_FREEBSD_AMD64
	{
		.base=_binary_stub_freebsd_amd64_start,
		.size=(size_t) &_binary_stub_freebsd_amd64_size
	},
#endif
#ifdef HAVE_LINUX_ARMV6
	{
		.base=_binary_stub_linux_armv6_start,
		.size=(size_t) &_binary_stub_linux_armv6_size
	},
#endif
	{ NULL, 0 }
};

static int update_descriptor(enum architecture_e arch, unsigned char *stub,
		size_t size, struct stub_data_64 *tmpdesc){
	struct stub_data_32 *desc;
	size_t i;
	for(i=0;i<size-sizeof(*desc);++i){ 
		desc=(struct stub_data_32 *)&stub[i];
		if(desc->magic == MAGIC){
			break;
		}
	}
	if (desc == NULL)
		return -1;
	if (arch == ARCH_AMD64){
		/* desc is in fact a 64 bits desc */
		memcpy(desc, tmpdesc, sizeof(*tmpdesc));
	} else {
		desc->data_base = tmpdesc->data_base;
		desc->data_len = tmpdesc->data_len;
		desc->banner_addr = tmpdesc->banner_addr;
		desc->banner_len = tmpdesc->banner_len;
		desc->type = tmpdesc->type;
		desc->hash_loops = tmpdesc->hash_loops;
		memcpy(desc->checksum, tmpdesc->checksum, sizeof(desc->checksum));
		memcpy(desc->password_salt, tmpdesc->password_salt, sizeof(desc->password_salt));
		memcpy(desc->encryption_salt, tmpdesc->encryption_salt, sizeof(desc->encryption_salt));
		memcpy(desc->authentication_key, tmpdesc->authentication_key, sizeof(desc->authentication_key));
	}
	return 0;
}

static int build_password(struct elf_file_s *file, struct stub_data_64 *desc){
	uint8_t encryptkey[AES128_KEY_LEN], IV[AES128_KEY_LEN], integrity[16];
	char *password;
	int rc;

	if (config.password != NULL) {
		password = config.password;
	} else {
		password = ask_password();
		if(password == NULL)
			return -1;
	}
	rc = generate_password_parameters(desc->encryption_salt, desc->password_salt);
	if (rc != 0)
		return -1;
	compute_session_keys_password(
			password, config.loops,
			encryptkey, IV, integrity,
			desc->encryption_salt,
			desc->password_salt);
#ifdef CRYPTO_DEBUG
	print_key("encrypt_salt", desc->encryption_salt, sizeof(desc->encryption_salt));
	print_key("password salt", desc->password_salt, sizeof(desc->password_salt));
	print_key("enckey", encryptkey, AES128_KEY_LEN);
	print_key("IV", IV, AES128_KEY_LEN);
	print_key("integrity", integrity, AES128_KEY_LEN);
#endif
	compute_checksum(file->data, file->size, integrity, desc->checksum);
#ifdef CRYPTO_DEBUG
	print_key("checksum", desc->checksum, 32);
#endif
	encrypt_payload(file->data, file->size, encryptkey, IV);
	return 0;
}

static int build_curve25519(struct elf_file_s *file, struct stub_data_64 *desc){
	uint8_t encryptkey[AES128_KEY_LEN], IV[AES128_KEY_LEN], integrity[AES128_KEY_LEN];
	struct key_file keydata;
	char keyfile[128];
	int rc;
	int i=1;
	FILE *f;

	ZERO(keydata);
	rc = generate_curve25519_parameters(desc->encryption_salt, keydata.master_key,
			desc->authentication_key);
	if (rc != 0)
		return -1;
	compute_session_keys(
			encryptkey, IV, integrity,
			keydata.master_key,
			desc->encryption_salt
			);
#ifdef CRYPTO_DEBUG
	print_key("enckey", encryptkey, AES128_KEY_LEN);
	print_key("IV", IV, AES128_KEY_LEN);
	print_key("integrity", integrity, AES128_KEY_LEN);
#endif
	compute_checksum(file->data, file->size, integrity, desc->checksum);
#ifdef CRYPTO_DEBUG
	print_key("checksum", desc->checksum, 32);
#endif
	encrypt_payload(file->data, file->size, encryptkey, IV);
	if(config.keyfile == NULL){
		snprintf(keyfile, sizeof(keyfile), "%s", "key");
		while(1){
			if(access(keyfile, F_OK) == 0){
				snprintf(keyfile, sizeof(keyfile),"key.%d",i);
				++i;
			} else {
				break;
			}
		}
	} else {
		snprintf(keyfile, sizeof(keyfile), "%s", config.keyfile);
	}
	f = fopen(keyfile,"w");
	if(f == NULL){
		printf("Error opening %s\n",keyfile);
		return -1;
	}
	keydata.magic[0]=KEY_FILE_MAGIC_0;
	keydata.magic[1]=KEY_FILE_MAGIC_1;
	keydata.magic[2]=KEY_FILE_MAGIC_2;
	keydata.magic[3]=KEY_FILE_MAGIC_3;
	snprintf(keydata.filename, sizeof(keydata.filename), "%s", keyfile);
	memcpy(keydata.authentication_key, desc->authentication_key,
			sizeof(desc->authentication_key));
	fwrite(&keydata, sizeof(keydata),1, f);
	fclose(f);
	printf("Key data written in file %s\n",keyfile);
	ZERO(keydata);
	ZERO(encryptkey);
	ZERO(IV);
	ZERO(integrity);
	return 0;
}

static int get_banner(char **banner, size_t *size){
	char buffer[4096];
	FILE *f;
	int r;

	if(config.bannerfile == NULL){
		*banner = NULL;
		*size = 0;
		return 0;
	}
	f = fopen(config.bannerfile, "r");
	if(f == NULL){
		printf("Cannot open banner file %s\n",config.bannerfile);
		return -1;
	}
	r=fread(buffer,1,sizeof(buffer)-1, f);
	fclose(f);
	if (r<0){
		printf("Error while reading banner file\n");
		return -1;
	}
	if (r==0){
		*banner=NULL;
		*size=0;
		return 0;
	}
	buffer[r]='\0';
	*size=r;
	*banner=malloc(r+1);
	memcpy(*banner, buffer, r+1);
	return 0;
}

static int build_packed_file(struct elf_file_s *file){
	unsigned char *stub;
	size_t size;
	int out;
	struct stub_data_64 tmp_desc;
	char *banner;
	size_t bannersize=0;
	enum architecture_e arch;
	enum os_e os;
	int rc;

	arch = elf_get_arch(file);
	os = elf_get_os(file);

	if (get_banner(&banner, &bannersize) < 0)
		return -1;
	if(banner != NULL)
		printf("banner: %d\n", (int)bannersize);
	switch (arch){
	case ARCH_x86:
		switch(os){
#ifdef HAVE_LINUX_X86
		case OS_LINUX:
			stub = stubs[STUB_LINUX_X86].base;
			size = stubs[STUB_LINUX_X86].size;
			elf_add_pheader_32(stub, BASE_ADDR + 4096, size, file->size + bannersize);
			break;
#endif
#ifdef HAVE_FREEBSD_X86
		case OS_FREEBSD:
			stub = stubs[STUB_FREEBSD_X86].base;
			size = stubs[STUB_FREEBSD_X86].size;
			elf_add_pheader_32(stub, BASE_ADDR + 4096, size, file->size + bannersize);
			break;
#endif
		default:
			printf("unsupported OS\n");
			break;
		}
		break;
	case ARCH_AMD64:
		switch(os){
		case OS_LINUX:
#ifdef HAVE_LINUX_AMD64
			stub = stubs[STUB_LINUX_AMD64].base;
			size = stubs[STUB_LINUX_AMD64].size;
			elf_add_pheader_64(stub, BASE_ADDR + 4096, size, file->size + bannersize);
			break;
#endif
		case OS_FREEBSD:
#ifdef HAVE_FREEBSD_AMD64
			stub = stubs[STUB_FREEBSD_AMD64].base;
			size = stubs[STUB_FREEBSD_AMD64].size;
			elf_add_pheader_64(stub, BASE_ADDR + 4096, size, file->size + bannersize);
			break;
#endif
		default:
			printf("Unsupported OS\n");
			break;
		}
		break;
		case ARCH_ARM:
			switch(os){
	#ifdef HAVE_LINUX_ARMV6
			case OS_LINUX:
				stub = stubs[STUB_LINUX_ARMV6].base;
				size = stubs[STUB_LINUX_ARMV6].size;
				elf_add_pheader_32(stub, BASE_ADDR + 4096, size, file->size + bannersize);
				break;
	#endif
			default:
				printf("Unsupported OS\n");
				break;
			}
		break;
	default:
		printf("Unsupported architecture\n");
		return -1;
	}

	tmp_desc.data_base = BASE_ADDR + size + 4096;
	tmp_desc.data_len = file->size;
	tmp_desc.banner_addr = tmp_desc.data_base + tmp_desc.data_len;
	tmp_desc.banner_len = bannersize;
	tmp_desc.type = config.pack_type;
	tmp_desc.hash_loops = config.loops;
	switch(config.pack_type){
	case PACK_TYPE_PASSWORD:
		rc = build_password(file, &tmp_desc);
		break;
	case PACK_TYPE_CURVE25519:
		rc = build_curve25519(file, &tmp_desc);
		break;
	}
	if (rc != 0)
		return rc;
	update_descriptor(arch, stub, size, &tmp_desc);
	elf_set_os(stub, os);
	out = open(config.outfile,O_WRONLY | O_CREAT,0755);
	if(out < 0){
		printf("Cannot open output file %s\n", config.outfile);
		return -1;
	}
	write(out, stub, size);
	write(out, file->data, file->size);
	if (banner != NULL)
		write(out, banner, bannersize);
	close(out);
	free(banner);
	return 0;
}
