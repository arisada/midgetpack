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

/* pack_common.c
 * This is where the packer payload executes
 */
#include "stub.h"
#include "config.h"
//#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdlib.h>
#include "sha256.h"
#include "aes.h"
#include "shared.h"

stub_data descriptor = {
	.magic = MAGIC,
};

#define PAGE_ALIGN(x) ((x + 0xfff)&~0xfff)
#define PAGE_ALIGN_DOWN(x) ((x) &~0xfff) 

void *memcpy(void *dest, void *src, size_t len){
	register size_t i;
	for(i=0;i<len;++i){
		((unsigned char *)dest)[i]=((unsigned char*)src)[i];
	}
	return dest;
}

static void write_dec(int v){
	char buffer[12]="";
	int i=0;
	unsigned int c=1000000000; /* 10**9 */
	unsigned int v2;
	if (v<0){
		buffer[i]='-';
		++i;
		v2 = (unsigned int)-v;
	} else {
		v2 = v;
	}
	while(c >= 1){
		int num = v2/c;
        v2 = v2 - c*num;
		buffer[i]= '0' + num;
		c = c/10;
		++i;
	}
	buffer[i]=0;
	write(1, buffer, i);
}

static void write_hex(unsigned int v){
	unsigned int c = 0xf0000000;
	char alphabet[]="0123456789abcdef";
	int i=0;
	char buffer[9]="";
	while(c > 0){
		buffer[i]=alphabet[(v & c) >> ((7-i)*4)];
		++i;
		c >>=4;
	}
	buffer[i]='\0';
	write(1,buffer,i);
}

#ifdef ARCH_AMD64
static void write_hex64(uint64_t v){
	uint64_t c = 0xf000000000000000;
	char alphabet[]="0123456789abcdef";
	int i=0;
	char buffer[17]="";
	while(c > 0){
		buffer[i]=alphabet[(v & c) >> ((15-i)*4)];
		++i;
		c >>=4;
	}
	buffer[i]='\0';
	write(1,buffer,i);
}
#endif

off_t strlen(char *s){
	register int i;
	for(i=0;s[i];++i)
		;
	return i;
}

void* memset(void *p, int val, size_t len){
	register size_t i;
	for(i=0;i<len;++i)
		((char *)p)[i]=val;
	return p;
}

int memcmp(const void *s1, const void *s2, size_t n){
	size_t i;
	for (i=0;i<n;++i){
		if(((uint8_t *)s1)[i] != ((uint8_t *)s2)[i]){
			return ((uint8_t *)s1)[i] < ((uint8_t *)s2)[i] ? -1:1;
		}
	}
	return 0;
}

char *strchr(const char *s, int c){
	int i;
	for(i=0;s[i]!='\0';++i)
		if(s[i] == c)
			return (char *)s + i;
	return NULL;
}

static int myprintf(const char *format, ...){
	va_list ap;
	const char *s;
	const char *p;
	union {
		int intv;
		char *charv;
		unsigned int uintv;
		uint64_t uint64v;
	} param;

	va_start(ap, format);
	p=s=format;
	while(*p != 0){
		while(*p && *p != '%')
			++p;
		if(p!=s){
			write(1, s, p-s);
			s=p;
		}
		if(*p == '%'){
			switch(p[1]){
				case 's':
					param.charv = va_arg(ap, char *);
					write(1, param.charv, strlen(param.charv));
					break;
				case 'd':
					param.intv = va_arg(ap, int);
					write_dec(param.intv);
					break;
				case 'x':
					param.uintv = va_arg(ap, unsigned int);
					write_hex(param.uintv);
					break;
				case 'p':
#if defined(ARCH_X86) || defined(ARCH_ARM)
					param.uintv = va_arg(ap, unsigned int);
					write_hex(param.uintv);
					break;
#else
					param.uint64v = va_arg(ap, uint64_t);
					write_hex64(param.uint64v);
					break;
#endif
				case '\0':
					goto end;
			}
			p += 2;
			s=p;
		}
	}
end:
	va_end(ap);
	return 0;
}

static int MP_MAP_ANON=0;

/* some constants have different values depending on OS */
static void init_constants(void){
	enum os_e os = get_os();
	switch(os){
	case OS_LINUX:
		MP_MAP_ANON = 0x20;
		break;
	case OS_FREEBSD:
		MP_MAP_ANON = 0x1000;
		break;
	default:
		break;
	}

}
static Elf_auxv_t *find_auxv(char **base){
	char **ptr = base;

	++ptr; /* argc */
	while(*ptr != NULL){
		++ptr; /* argv[i] */
	}
	++ptr;
	while(*ptr != NULL){
		++ptr; /* environ[i] */
	}
	++ptr;
	return (Elf_auxv_t *)ptr;
}

static void fix_auxv(Elf_auxv_t *auxv, Elf_Ehdr *elf, void *program_base, void *interp_base){
	int i;
	for(i=0;auxv[i].a_type != 0;++i){
#ifdef LOADER_DEBUG
		myprintf("aux %d : %p -> ",auxv[i].a_type,
			auxv[i].a_un.a_val);
#endif
		switch(auxv[i].a_type){
			case AT_PHDR:
				auxv[i].a_un.a_val = (Elf_Addr)program_base + elf->e_phoff;
				break;
			case AT_ENTRY:
				auxv[i].a_un.a_val = elf->e_entry;
				break;
			case AT_PHNUM:
				auxv[i].a_un.a_val = elf->e_phnum;
				break;
			case AT_BASE:
				auxv[i].a_un.a_val = PAGE_ALIGN_DOWN((Elf_Addr)interp_base);
				break;
		}
#ifdef LOADER_DEBUG
		myprintf("%p\n",auxv[i].a_un.a_val);
#endif
	}
}

static size_t elf_total_size(Elf_Phdr *phs, int n){
	Elf_Phdr *first=NULL, *last=NULL;
	int i;
	size_t totallen;
	for(i=0;i<n;++i){
		if(phs[i].p_type == PT_LOAD){
			if(first == NULL)
				first=&phs[i];
			last=&phs[i];
		}
	}
	totallen = last->p_vaddr + last->p_memsz - PAGE_ALIGN_DOWN(first->p_vaddr);
#ifdef LOADER_DEBUG
	myprintf("total len %d %x\n",totallen,totallen);
#endif
	return totallen;
}

static void clean_pages(char *base, Elf_Phdr *p){
	size_t len = p->p_vaddr - PAGE_ALIGN_DOWN(p->p_vaddr);
	if(len > 0){
		memset(base + PAGE_ALIGN_DOWN(p->p_vaddr), 0, len);
	}

	len = p->p_memsz - p->p_filesz;
	
	if(len >0){
		memset(base + p->p_vaddr + p->p_filesz, 0, len);
	}

	len = PAGE_ALIGN(p->p_vaddr + p->p_memsz) - (p->p_vaddr + p->p_memsz);
	if(len > 0){
		memset(base + p->p_vaddr + p->p_memsz, 0, len);
	}
}
	

/* map the interpreter, return the entrypoint */
/* returns NULL if program has no interpreter */
static void *map_loader(Elf_Ehdr *elf, Elf_Phdr *phs, void **interpr_base_p){
	int i;
	char interp[128];
	size_t len;
	char *interp_base = NULL;
	int fd;
	char header[1024];
	void *ret;
#ifdef ARCH_X86
	static char bsd_interp[]="/libexec/ld-elf.so.1";
	static char bsd_interp32[]="/libexec/ld-elf32.so.1";
	int changed_interp=0;
#endif	
	for (i=0; i<elf->e_phnum; ++i){
		if(phs[i].p_type == PT_INTERP)
			break;
	}
	if (i>= elf->e_phnum)
		return NULL;
	len = phs[i].p_filesz;
	if (len > sizeof(interp) -1)
		len = sizeof(interp) -1;
	memcpy(interp, ((char *)elf) + phs[i].p_offset, len);
	interp[len]='\0';
#ifdef ARCH_X86
	/* FreeBSD requires the kernel to modify the loader name when */
	/* running on x86-64. Bad design IMO, here's a workaround     */
	if(memcmp(interp,bsd_interp, sizeof(bsd_interp))==0){
			memcpy(interp,bsd_interp32,sizeof(bsd_interp32));
			changed_interp=1;
	}
#endif
#ifdef LOADER_DEBUG
	myprintf("Opening %s\n",interp);
#endif
	fd = open(interp, O_RDONLY);
#ifdef ARCH_X86
	if (fd < 0 && changed_interp){
#ifdef LOADER_DEBUG
		myprintf("Fallback on %s\n", bsd_interp);
#endif
		memcpy(interp, bsd_interp, sizeof(bsd_interp));
		fd = open(bsd_interp, O_RDONLY);
	}
#endif
	if (fd <0){
		myprintf("Could not open interpreter %s (%d), mismatch 32/64 bits ?\n",
			interp, fd);
		exit(1);
	}
	read(fd, header, 1024);
	elf=(Elf_Ehdr *) header;
	phs=(Elf_Phdr *) ((char *)header + elf->e_phoff);
#ifdef LOADER_DEBUG
	myprintf("Elf header at %x\n",header);
	myprintf("%d pheaders starting at %p\n",elf->e_phnum,elf->e_phoff);
#endif

	len = elf_total_size(phs, elf->e_phnum);
	len = PAGE_ALIGN(len);
	interp_base = mmap(NULL, len , PROT_READ|PROT_WRITE,
			MAP_PRIVATE | MP_MAP_ANON, -1, 0);
	if (interp_base == NULL){
		myprintf("mapping error\n");
		return NULL;
	}
#ifdef LOADER_DEBUG
	myprintf("base mapped at %p\n",interp_base);
#endif

#if 0	
	for (i=0;i<elf->e_phnum; ++i){
#ifdef LOADER_DEBUG
		myprintf("pheader %d:%p type %d vaddr %p filesz %x\n", i,
			&phs[i],
			phs[i].p_type, phs[i].p_vaddr, phs[i].p_filesz);
#endif
		if(phs[i].p_type == PT_LOAD){
				len = elf_total_size(phs, elf->e_phnum);
				len = PAGE_ALIGN(len);
#ifdef LOADER_DEBUG
				myprintf("first map len: %d\n",len);
#endif
				interp_base = mmap(NULL, len
					, PROT_EXEC | PROT_READ | PROT_WRITE,
					MAP_PRIVATE,
					fd, 0);
				if (interp_base == NULL){
					myprintf("mapping error\n");
					return NULL;
				}
#ifdef LOADER_DEBUG
				myprintf("base mapped at %p\n",interp_base);
#endif
				clean_pages(interp_base, &phs[i]);
				/* clean unmapped memory that was overly mapped */
				//memset(interp_base + phs[i].p_memsz, 0, len - phs[i].p_memsz);
				++i;
				break;
		}
	}
#endif
	/* first page loaded, now fixed mmap of the others */
	for(i=0;i<elf->e_phnum; ++i){
		if(phs[i].p_type == PT_LOAD){
#ifdef LOADER_DEBUG
				myprintf("pheader %d:%p type %d vaddr %p filesz %p\n", i,
				&phs[i],
				phs[i].p_type, phs[i].p_vaddr, phs[i].p_filesz);
#endif

				ret = mmap(
					interp_base + PAGE_ALIGN_DOWN(phs[i].p_vaddr),
					PAGE_ALIGN((phs[i].p_vaddr & 0xfff) + phs[i].p_memsz),
					PROT_EXEC | PROT_READ | PROT_WRITE,
					MAP_PRIVATE |MAP_FIXED,
					fd, PAGE_ALIGN_DOWN(phs[i].p_offset));
				if (ret == NULL){
					myprintf("mapping error\n");
					return NULL;
				}
#ifdef LOADER_DEBUG
				myprintf("page mapped at %p\n",ret);
#endif
				clean_pages(interp_base, &phs[i]);
		}
	}
	close(fd);
#ifdef LOADER_DEBUG
	myprintf("interpreter entrypoint at %p\n",interp_base +elf->e_entry);
#endif
	*interpr_base_p = interp_base;
	return (void *)(interp_base + elf->e_entry);
}

uint8_t entropy_pool[SHA256_DIGEST_LEN];
/* We have 3 entropy sources:
 * - random values given in auxv at startup (32 bytes)
 * - /dev/urandom
 * - rdtsc + gettimeofday
 */
static void reseed_pool(Elf_auxv_t *auxv){
	SHA256_CTX ctx;
	int i;
	int fd;
	uint8_t buffer[32];
	uint32_t tsc[2];

	SHA256_Init(&ctx);

	gettsc(tsc);
	SHA256_Update(&ctx, tsc, sizeof(tsc));
#ifdef AT_RANDOM
	for (i=0; auxv[i].a_type != AT_NULL; ++i){
		switch(auxv[i].a_type){
		case AT_RANDOM:
			/* 16 random bytes */
			SHA256_Update(&ctx, (void *)auxv[i].a_un.a_val, 16);
			break;
		}
	}
#endif
	gettsc(tsc);
	SHA256_Update(&ctx, tsc, sizeof(tsc));

	fd = open("/dev/urandom", O_RDONLY);
	if(fd >= 0){
		read(fd, buffer, sizeof(buffer));
		SHA256_Update(&ctx, buffer, sizeof(buffer));
		close(fd);
	} else {
		fd = open("/dev/random", O_RDONLY);
		if (fd >= 0){
			/* /dev/random is more expensive to use */
			read(fd, buffer, 8);
			SHA256_Update(&ctx, buffer, 8);
			close(fd);
		}
	}
	for (i=0;i<32;++i){
		getpid();
		gettsc(tsc);
		SHA256_Update(&ctx, tsc, sizeof(tsc));
	}
	SHA256_Final(entropy_pool, &ctx);
}

int get_random(uint8_t *buffer, size_t len){
	int i;
	uint8_t shabuf[SHA256_DIGEST_LEN];
	HMAC_SHA256_CTX ctx;
	size_t left;

	for (i=0, left=len; left > 0 ; ++i){
		HMAC_SHA256_Init(&ctx, entropy_pool, 32);
		HMAC_SHA256_Update(&ctx, "generate", 8);
		HMAC_SHA256_Final(shabuf, &ctx);

		HMAC_SHA256_Init(&ctx, entropy_pool, 32);
		HMAC_SHA256_Update(&ctx, "reseed", 6);
		HMAC_SHA256_Final(entropy_pool, &ctx);

		memcpy(buffer + i*SHA256_DIGEST_LEN, shabuf,
				left > SHA256_DIGEST_LEN ? SHA256_DIGEST_LEN: left);
		if (left > SHA256_DIGEST_LEN)
			left -= SHA256_DIGEST_LEN;
		else
			left = 0;
	}
	ZERO(shabuf);
	ZERO(ctx);

	return len;
}

static void decrypt_payload(void *payload, size_t len, uint8_t encryptkey[16],
		uint8_t IV[16]){
	AES_CTX ctx;
	int pad = (16 - len%16)% 16;

	/* blocks must be 16 bytes padded */
	len += pad;
#ifdef CRYPTO_DEBUG
	myprintf("Aes_decrypt (%x %d) = ", *(uint32_t *)payload, len);
#endif
	AES_set_key(&ctx, encryptkey, IV, AES_MODE_128);
	AES_convert_key(&ctx);
	/* do the encryption in-place to spare memory */
	AES_cbc_decrypt(&ctx, payload, payload, len);
#ifdef CRYPTO_DEBUG
	myprintf("%x\n", *(uint32_t *)payload);
#endif
	ZERO(ctx);
}

static void ask_password(char *pwd, size_t len){
	size_t i;
	int rc;
	myprintf("Password: ");
	for(i=0;i<len;++i){
		rc = read(0, &pwd[i], 1);
		if (rc < 0){
			pwd[i]='\0';
			return;
		}
		if(pwd[i]=='\n' || pwd[i]=='\r'){
			pwd[i]='\0';
			return;
		}
	}
	pwd[len-1]='\0';
	return;
}
#ifdef CRYPTO_DEBUG
void print_key(const char *name, uint8_t *key, int len){
	int i;
	uint32_t *v=(uint32_t *)key;
	myprintf("%s: ",name);
	for (i=0;i<len/4;++i){
		myprintf("%x ", v[i]);
	}
	myprintf("\n");
}
#endif

static void decrypt_password(uint8_t *encryptkey, uint8_t *IV, uint8_t *integrity){
	char password[128];

	ask_password(password, sizeof(password));
#ifdef CRYPTO_DEBUG
	print_key("encrypt_salt",descriptor.encryption_salt, sizeof(descriptor.encryption_salt));
	print_key("password salt", descriptor.password_salt, sizeof(descriptor.password_salt));
#endif
	compute_session_keys_password(
			password, descriptor.hash_loops,
			encryptkey, IV, integrity,
			descriptor.encryption_salt,
			descriptor.password_salt);
	ZERO(password);
}

static void decrypt_curve25519(uint8_t *encryptkey, uint8_t *IV, uint8_t *integrity){
	uint8_t private[CURVE25519_KEY_LEN];
	uint8_t pubkey[CURVE25519_KEY_LEN];
	uint8_t shared_secret[CURVE25519_KEY_LEN];
	uint8_t authentication[SHA256_DIGEST_LEN];
	uint8_t master_key[AES128_KEY_LEN];
	struct curve25519_request req;
	struct curve25519_reply reply;
	char buffer[128];
	HMAC_SHA256_CTX ctx;
	AES_CTX aes;
	int rc;

	get_random(private, CURVE25519_KEY_LEN);
	crypto_scalarmult_base(pubkey, private);

	memcpy(req.pubkey, pubkey, sizeof(pubkey));
	HMAC_SHA256_Init(&ctx, descriptor.authentication_key,
			sizeof(descriptor.authentication_key));
	HMAC_SHA256_Update(&ctx, pubkey, sizeof(pubkey));
	HMAC_SHA256_Final(authentication, &ctx);
	memcpy(req.authentication, authentication, sizeof(req.authentication));
#ifdef CRYPTO_DEBUG
	print_key("authentication key", descriptor.authentication_key,
			sizeof(descriptor.authentication_key));
	print_key("pubkey", req.pubkey, sizeof(req.pubkey));
	print_key("authentication", req.authentication, sizeof(req.authentication));
#endif
	b64_encode(buffer, sizeof(buffer), (uint8_t *)&req, sizeof(req));
	myprintf("challenge:\n%s\n", buffer);
	rc = read(0, buffer, sizeof(buffer) -1);
	if(rc <= 0){
		myprintf("Reading fail\n");
		exit(1);
	}
	buffer[rc]=0;
	b64_decode((uint8_t *)&reply, sizeof(reply),buffer, strlen(buffer));
	crypto_scalarmult(shared_secret, private, reply.pubkey);
	HMAC_SHA256_Init(&ctx, descriptor.authentication_key,
			sizeof(descriptor.authentication_key));
	HMAC_SHA256_Update(&ctx, shared_secret, CURVE25519_KEY_LEN);
	HMAC_SHA256_Update(&ctx, reply.encrypted_master, AES128_KEY_LEN);
	HMAC_SHA256_Final(authentication, &ctx);

	if(memcmp(authentication, reply.authentication,
			sizeof(reply.authentication)) != 0){
		myprintf("Curve25519 key exchange failed !\n");
		exit(1);
	}

	AES_set_key(&aes, &shared_secret[0], &shared_secret[16],AES_MODE_128);
	// AES decryption fudge */
	AES_convert_key(&aes);
	AES_cbc_decrypt(&aes, reply.encrypted_master, master_key, AES128_KEY_LEN);
	compute_session_keys(encryptkey,IV,integrity,master_key, descriptor.encryption_salt);
	ZERO(aes);
	ZERO(ctx);
	ZERO(buffer);
	ZERO(req);
	ZERO(reply);
	ZERO(master_key);
	ZERO(authentication);
	ZERO(shared_secret);
	ZERO(pubkey);
	ZERO(private);
}

static void decrypt(){
	uint8_t encryptkey[AES128_KEY_LEN], IV[AES128_KEY_LEN],
			integrity[16],
			checksum[SHA256_DIGEST_LEN];

	switch(descriptor.type){
	case PACK_TYPE_PASSWORD:
		decrypt_password(encryptkey, IV, integrity);
		break;
	case PACK_TYPE_CURVE25519:
		decrypt_curve25519(encryptkey, IV, integrity);
		break;
	}
#ifdef CRYPTO_DEBUG
	print_key("enckey", encryptkey, AES128_KEY_LEN);
	print_key("IV", IV, AES128_KEY_LEN);
	print_key("integrity", integrity, AES128_KEY_LEN);
#endif
	decrypt_payload((void *)descriptor.data_base, descriptor.data_len,
			encryptkey, IV);
	compute_checksum((void *)descriptor.data_base, descriptor.data_len,
			integrity, checksum);
#ifdef CRYPTO_DEBUG
	print_key("file cheksum", descriptor.checksum, 32);
	print_key("calculated checksum", checksum, 32);
#endif
	if(memcmp(checksum, descriptor.checksum, SHA256_DIGEST_LEN) != 0){
			myprintf("Integrity error. Good password ?\n");
			exit(1);
	}
	ZERO(encryptkey);
	ZERO(integrity);
	ZERO(IV);
}

void *get_oep(char **base){
	Elf_Ehdr *elf = (void *)descriptor.data_base;
	Elf_Phdr *phs;
	Elf_auxv_t *auxv;
	int pcount;
	int i=0;
	void *interpr=NULL;
	void *interpr_base=NULL;
	void *entry=NULL;
	void *ret;
	void *program_base = NULL;

	myprintf("starting stub ...\n" );
	init_constants();
	auxv = find_auxv(base);

	reseed_pool(auxv);
	if (descriptor.banner_len > 0){
		write(1, (void *)descriptor.banner_addr, descriptor.banner_len);
	}
	decrypt();
	phs = (Elf_Phdr *)(descriptor.data_base + elf->e_phoff);
	pcount = elf->e_phnum;
	for (i=0;i<pcount;++i){
		if(phs[i].p_type == PT_LOAD){
			ret = mmap((void *)PAGE_ALIGN_DOWN(phs[i].p_vaddr),
					PAGE_ALIGN((phs[i].p_vaddr & 0xfff) + phs[i].p_memsz),
					PROT_EXEC | PROT_READ | PROT_WRITE, 
					MAP_PRIVATE | MAP_FIXED  | MP_MAP_ANON,
					-1, 0);
			if (ret == NULL){
				return NULL;
			}
			memcpy((void *)phs[i].p_vaddr, 
				(void *)(descriptor.data_base + phs[i].p_offset),
				phs[i].p_filesz);
			if(program_base == NULL)
				program_base=(void *)PAGE_ALIGN_DOWN((Elf_Addr)ret);
#ifdef LOADER_DEBUG
			myprintf("Loaded program header %d at %p (%d)\n", i, phs[i].p_vaddr, phs[i].p_filesz);
#endif
		}
	}
	entry = (void *) elf->e_entry;
	interpr = map_loader(elf, phs, &interpr_base);
	fix_auxv(auxv, elf, program_base, interpr_base);
	/* Don't let the whole unpacked binary in memory */
	munmap((void *)PAGE_ALIGN_DOWN(descriptor.data_base),
			PAGE_ALIGN(descriptor.data_len + (descriptor.data_base & 0xfff)));
	if (interpr != NULL)
		return interpr;
	else	
		return entry;
}
