/*************************** HEADER FILES ***************************/
#include "sha256.h"

// Permit paired word loads without violating the state array's effective type.
typedef SHA256_DWORD SHA256_ALIAS __attribute__((__may_alias__));

/****************************** MACROS ******************************/
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) ((y) ^ (((x) ^ (y)) & ((y) ^ (z))))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
static const SHA256_WORD GLOBAL_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/*********************** FUNCTION DEFINITIONS ***********************/
// RFC 0033: CKB-VM fuses this exact add/sltu/add/sltu/or sequence into
// one ADC (one cycle). Only the low 32 bits of the three-term sum are needed;
// the carry outputs are discarded. Early-clobber constraints keep all three
// registers distinct, as required by the VM's pattern matcher. Keep the whole
// sequence in one asm block so the compiler cannot reorder or remove it.
static inline __attribute__((always_inline)) SHA256_WORD
sha256_add3(SHA256_WORD a, SHA256_WORD b, SHA256_WORD c) {
#if defined(__riscv) && __riscv_xlen == 64
    __asm__(
        "add %0, %0, %1\n\t"
        "sltu %1, %0, %1\n\t"
        "add %0, %0, %2\n\t"
        "sltu %2, %0, %2\n\t"
        "or %1, %1, %2"
        : "+&r"(a), "+&r"(b), "+&r"(c));
    return a;
#else
    return a + b + c;
#endif
}

// Keep round constants in word registers so LLVM emits adjacent lui/addiw
// instructions, which CKB-VM can fuse into a single constant load (RFC 0033).
static inline SHA256_WORD sha256_round_constant(SHA256_WORD k) {
#if defined(__riscv) && __riscv_xlen == 64
    __asm__("" : "+r"(k));
#endif
    return k;
}

#define SHA256_ROUND(a, b, c, d, e, f, g, h, mi, ki)                     \
    do {                                                                 \
        SHA256_WORD k = sha256_round_constant(ki);                       \
        SHA256_WORD t1 =                                                 \
            sha256_add3(sha256_add3((h), EP1(e), CH(e, f, g)), (mi), k); \
        (d) += t1;                                                       \
        (h) = sha256_add3(t1, EP0(a), MAJ(a, b, c));                     \
    } while (0)

// Blocks are copied into ctx->data before compression, providing the alignment
// needed for the 64-bit loads even when callers supply unaligned byte buffers.
void sha256_transform(SHA256_CTX *ctx, const SHA256_BYTE data[]) {
    SHA256_WORD a, b, c, d, e, f, g, h;
    SHA256_WORD m[64];
    const SHA256_ALIAS *data64 = (const SHA256_ALIAS *)data;

#pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) {
        SHA256_DWORD temp = __builtin_bswap64(data64[i]);
        m[2 * i] = (SHA256_WORD)(temp >> 32);
        m[2 * i + 1] = (SHA256_WORD)temp;
    }

    // Load state using 64-bit operations
    const SHA256_ALIAS *state64 = (const SHA256_ALIAS *)ctx->state;
    SHA256_DWORD s01 = state64[0];
    SHA256_DWORD s23 = state64[1];
    SHA256_DWORD s45 = state64[2];
    SHA256_DWORD s67 = state64[3];
    a = (SHA256_WORD)s01;
    b = (SHA256_WORD)(s01 >> 32);
    c = (SHA256_WORD)s23;
    d = (SHA256_WORD)(s23 >> 32);
    e = (SHA256_WORD)s45;
    f = (SHA256_WORD)(s45 >> 32);
    g = (SHA256_WORD)s67;
    h = (SHA256_WORD)(s67 >> 32);

#pragma GCC unroll 2
    for (int i = 0; i < 16; i += 8) {
        SHA256_ROUND(a, b, c, d, e, f, g, h, m[i], GLOBAL_K[i]);
        SHA256_ROUND(h, a, b, c, d, e, f, g, m[i + 1], GLOBAL_K[i + 1]);
        SHA256_ROUND(g, h, a, b, c, d, e, f, m[i + 2], GLOBAL_K[i + 2]);
        SHA256_ROUND(f, g, h, a, b, c, d, e, m[i + 3], GLOBAL_K[i + 3]);
        SHA256_ROUND(e, f, g, h, a, b, c, d, m[i + 4], GLOBAL_K[i + 4]);
        SHA256_ROUND(d, e, f, g, h, a, b, c, m[i + 5], GLOBAL_K[i + 5]);
        SHA256_ROUND(c, d, e, f, g, h, a, b, m[i + 6], GLOBAL_K[i + 6]);
        SHA256_ROUND(b, c, d, e, f, g, h, a, m[i + 7], GLOBAL_K[i + 7]);
    }

#pragma GCC unroll 6
    for (int i = 16; i < 64; i += 8) {
        m[i] =
            sha256_add3(m[i - 16], SIG1(m[i - 2]), SIG0(m[i - 15])) + m[i - 7];
        SHA256_ROUND(a, b, c, d, e, f, g, h, m[i], GLOBAL_K[i]);
        m[i + 1] =
            sha256_add3(m[i - 15], SIG1(m[i - 1]), SIG0(m[i - 14])) + m[i - 6];
        SHA256_ROUND(h, a, b, c, d, e, f, g, m[i + 1], GLOBAL_K[i + 1]);
        m[i + 2] =
            sha256_add3(m[i - 14], SIG1(m[i]), SIG0(m[i - 13])) + m[i - 5];
        SHA256_ROUND(g, h, a, b, c, d, e, f, m[i + 2], GLOBAL_K[i + 2]);
        m[i + 3] =
            sha256_add3(m[i - 13], SIG1(m[i + 1]), SIG0(m[i - 12])) + m[i - 4];
        SHA256_ROUND(f, g, h, a, b, c, d, e, m[i + 3], GLOBAL_K[i + 3]);
        m[i + 4] =
            sha256_add3(m[i - 12], SIG1(m[i + 2]), SIG0(m[i - 11])) + m[i - 3];
        SHA256_ROUND(e, f, g, h, a, b, c, d, m[i + 4], GLOBAL_K[i + 4]);
        m[i + 5] =
            sha256_add3(m[i - 11], SIG1(m[i + 3]), SIG0(m[i - 10])) + m[i - 2];
        SHA256_ROUND(d, e, f, g, h, a, b, c, m[i + 5], GLOBAL_K[i + 5]);
        m[i + 6] =
            sha256_add3(m[i - 10], SIG1(m[i + 4]), SIG0(m[i - 9])) + m[i - 1];
        SHA256_ROUND(c, d, e, f, g, h, a, b, m[i + 6], GLOBAL_K[i + 6]);
        m[i + 7] = sha256_add3(m[i - 9], SIG1(m[i + 5]), SIG0(m[i - 8])) + m[i];
        SHA256_ROUND(b, c, d, e, f, g, h, a, m[i + 7], GLOBAL_K[i + 7]);
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    static const SHA256_DWORD initial_state[4] = {
        0xbb67ae856a09e667ULL, 0xa54ff53a3c6ef372ULL, 0x9b05688c510e527fULL,
        0x5be0cd191f83d9abULL};
    __builtin_memcpy(ctx->state, initial_state, sizeof(initial_state));
}

void sha256_update(SHA256_CTX *ctx, const SHA256_BYTE data[],
                   SHA256_DWORD len) {
    if (len == 0) {
        return;
    }
    // Complete a buffered block first, then copy whole blocks and the tail.
    if (ctx->datalen != 0) {
        SHA256_WORD space = 64 - ctx->datalen;
        if (len < space) {
            __builtin_memcpy(ctx->data + ctx->datalen, data, len);
            ctx->datalen += len;
            return;
        }
        __builtin_memcpy(ctx->data + ctx->datalen, data, space);
        sha256_transform(ctx, ctx->data);
        ctx->bitlen += 512;
        data += space;
        len -= space;
        ctx->datalen = 0;
    }
    // Use a 64-bit remaining length so updates larger than 4 GiB cannot wrap.
    while (len >= 64) {
        __builtin_memcpy(ctx->data, data, 64);
        sha256_transform(ctx, ctx->data);
        ctx->bitlen += 512;
        data += 64;
        len -= 64;
    }
    if (len != 0) {
        __builtin_memcpy(ctx->data, data, len);
        ctx->datalen = len;
    }
}

void sha256_final(SHA256_CTX *ctx, SHA256_BYTE hash[]) {
    SHA256_WORD i;

    i = ctx->datalen;

    // Pad whatever data is left in the buffer.
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        __builtin_memset(&ctx->data[i], 0, 56 - i);
    } else {
        ctx->data[i++] = 0x80;
        __builtin_memset(&ctx->data[i], 0, 64 - i);
        sha256_transform(ctx, ctx->data);
        __builtin_memset(ctx->data, 0, 56);
    }

    // Append to the padding the total message's length in bits and transform.
    ctx->bitlen += ctx->datalen * 8;
    SHA256_DWORD bitlen = __builtin_bswap64(ctx->bitlen);
    __builtin_memcpy(ctx->data + 56, &bitlen, 8);
    sha256_transform(ctx, ctx->data);

    // The digest destination has byte alignment; memcpy also allows aligned
    // callers to retain wide stores without requiring that alignment in the API.
#pragma GCC unroll 4
    for (i = 0; i < 4; ++i) {
        SHA256_DWORD s;
        __builtin_memcpy(&s, ctx->state + 2 * i, 8);
        s = __builtin_bswap64((s >> 32) | (s << 32));
        __builtin_memcpy(hash + 8 * i, &s, 8);
    }
}
