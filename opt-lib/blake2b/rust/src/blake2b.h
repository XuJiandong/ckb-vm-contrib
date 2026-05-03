/*
   BLAKE2 reference source code package - reference C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/

#ifndef BLAKE2B_H
#define BLAKE2B_H

/****************************** MACROS ******************************/
#define NULL ((void *)0)

#define BLAKE2B_BLOCKBYTES 128
#define BLAKE2B_OUTBYTES 64
#define BLAKE2B_KEYBYTES 64
#define BLAKE2B_SALTBYTES 16
#define BLAKE2B_PERSONALBYTES 16

/**************************** DATA TYPES ****************************/
// 8-bit byte
typedef unsigned char BLAKE2B_BYTE;
// 64-bit word
typedef unsigned long long BLAKE2B_WORD;
// 64-bit length/size type
typedef unsigned long long BLAKE2B_SIZE;

typedef struct {
    BLAKE2B_WORD h[8];
    BLAKE2B_WORD t[2];
    BLAKE2B_WORD f[2];
    BLAKE2B_BYTE buf[BLAKE2B_BLOCKBYTES];
    BLAKE2B_SIZE buflen;
    BLAKE2B_SIZE outlen;
    BLAKE2B_BYTE last_node;
} BLAKE2B_STATE;

typedef struct {
    BLAKE2B_BYTE digest_length;
    BLAKE2B_BYTE key_length;
    BLAKE2B_BYTE fanout;
    BLAKE2B_BYTE depth;
    unsigned int leaf_length;
    unsigned int node_offset;
    unsigned int xof_length;
    BLAKE2B_BYTE node_depth;
    BLAKE2B_BYTE inner_length;
    BLAKE2B_BYTE reserved[14];
    BLAKE2B_BYTE salt[BLAKE2B_SALTBYTES];
    BLAKE2B_BYTE personal[BLAKE2B_PERSONALBYTES];
} __attribute__((packed)) BLAKE2B_PARAM;

/* Padded structs result in a compile-time error */
enum { BLAKE2B_DUMMY = 1 / (sizeof(BLAKE2B_PARAM) == BLAKE2B_OUTBYTES) };

/*********************** FUNCTION DECLARATIONS **********************/
int ckb_blake2b_init(BLAKE2B_STATE *S, BLAKE2B_SIZE outlen);
int ckb_blake2b_init_personal(BLAKE2B_STATE *S, BLAKE2B_SIZE outlen,
                               const BLAKE2B_BYTE *personal);
int blake2b_init(BLAKE2B_STATE *S, BLAKE2B_SIZE outlen);
int blake2b_init_key(BLAKE2B_STATE *S, BLAKE2B_SIZE outlen, const void *key,
                     BLAKE2B_SIZE keylen);
int blake2b_init_param(BLAKE2B_STATE *S, const BLAKE2B_PARAM *P);
int blake2b_update(BLAKE2B_STATE *S, const void *in, BLAKE2B_SIZE inlen);
int blake2b_final(BLAKE2B_STATE *S, void *out, BLAKE2B_SIZE outlen);
int blake2b(void *out, BLAKE2B_SIZE outlen, const void *in, BLAKE2B_SIZE inlen,
            const void *key, BLAKE2B_SIZE keylen);
int blake2(void *out, BLAKE2B_SIZE outlen, const void *in, BLAKE2B_SIZE inlen,
           const void *key, BLAKE2B_SIZE keylen);

#endif  // BLAKE2B_H
