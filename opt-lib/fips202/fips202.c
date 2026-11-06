/* Based on the public domain implementation in
 * crypto_hash/keccakc512/simple/ from http://bench.cr.yp.to/supercop.html
 * by Ronny Van Keer
 * and the public domain "TweetFips202" implementation
 * from https://twitter.com/tweetfips202
 * by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe */

#include "fips202.h"

#define NROUNDS 24
#define ROL(a, offset) (((a) << (offset)) ^ ((a) >> (64 - (offset))))

/*************************************************
 * Name:        load64
 *
 * Description: Load 8 bytes into FIPS202_UINT64 in little-endian order
 *
 * Arguments:   - const FIPS202_UINT8 *x: pointer to input byte array
 *
 * Returns the loaded 64-bit unsigned integer
 **************************************************/
static FIPS202_UINT64 load64(const FIPS202_UINT8* x) {
    FIPS202_UINT64 r;
    __builtin_memcpy(&r, x, 8);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap64(r);
#else
    return r;
#endif
}

/*************************************************
 * Name:        store64
 *
 * Description: Store a 64-bit integer to a byte array in little-endian order
 *
 * Arguments:   - FIPS202_UINT8 *x: pointer to the output byte array
 *              - FIPS202_UINT64 u: input 64-bit unsigned integer
 **************************************************/
static void store64(FIPS202_UINT8* x, FIPS202_UINT64 u) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    u = __builtin_bswap64(u);
#endif
    __builtin_memcpy(x, &u, 8);
}

/* Keccak round constants */
static const FIPS202_UINT64 KeccakF_RoundConstants[NROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

/*************************************************
 * Name:        KeccakF1600_StatePermute
 *
 * Description: The Keccak F1600 Permutation
 *
 * Arguments:   - FIPS202_UINT64 *state: pointer to input/output Keccak state
 **************************************************/
static void KeccakF1600_StatePermute(FIPS202_UINT64* state) {
    int round;

    FIPS202_UINT64 Aba, Abe, Abi, Abo, Abu;
    FIPS202_UINT64 Aga, Age, Agi, Ago, Agu;
    FIPS202_UINT64 Aka, Ake, Aki, Ako, Aku;
    FIPS202_UINT64 Ama, Ame, Ami, Amo, Amu;
    FIPS202_UINT64 Asa, Ase, Asi, Aso, Asu;
    FIPS202_UINT64 BCa, BCe, BCi, BCo, BCu;
    FIPS202_UINT64 Da, De, Di, Do, Du;
    FIPS202_UINT64 Eba, Ebe, Ebi, Ebo, Ebu;
    FIPS202_UINT64 Ega, Ege, Egi, Ego, Egu;
    FIPS202_UINT64 Eka, Eke, Eki, Eko, Eku;
    FIPS202_UINT64 Ema, Eme, Emi, Emo, Emu;
    FIPS202_UINT64 Esa, Ese, Esi, Eso, Esu;

    Aba = state[0];
    Abe = state[1];
    Abi = state[2];
    Abo = state[3];
    Abu = state[4];
    Aga = state[5];
    Age = state[6];
    Agi = state[7];
    Ago = state[8];
    Agu = state[9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

#pragma GCC unroll 24
    for (round = 0; round < NROUNDS; round += 2) {
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = ROL(Age, 44);
        Aki ^= Di;
        BCi = ROL(Aki, 43);
        Amo ^= Do;
        BCo = ROL(Amo, 21);
        Asu ^= Du;
        BCu = ROL(Asu, 14);
        Eba = BCa ^ ((~BCe) & BCi);
        Eba ^= KeccakF_RoundConstants[round];
        Ebe = BCe ^ ((~BCi) & BCo);
        Ebi = BCi ^ ((~BCo) & BCu);
        Ebo = BCo ^ ((~BCu) & BCa);
        Ebu = BCu ^ ((~BCa) & BCe);

        Abo ^= Do;
        BCa = ROL(Abo, 28);
        Agu ^= Du;
        BCe = ROL(Agu, 20);
        Aka ^= Da;
        BCi = ROL(Aka, 3);
        Ame ^= De;
        BCo = ROL(Ame, 45);
        Asi ^= Di;
        BCu = ROL(Asi, 61);
        Ega = BCa ^ ((~BCe) & BCi);
        Ege = BCe ^ ((~BCi) & BCo);
        Egi = BCi ^ ((~BCo) & BCu);
        Ego = BCo ^ ((~BCu) & BCa);
        Egu = BCu ^ ((~BCa) & BCe);

        Abe ^= De;
        BCa = ROL(Abe, 1);
        Agi ^= Di;
        BCe = ROL(Agi, 6);
        Ako ^= Do;
        BCi = ROL(Ako, 25);
        Amu ^= Du;
        BCo = ROL(Amu, 8);
        Asa ^= Da;
        BCu = ROL(Asa, 18);
        Eka = BCa ^ ((~BCe) & BCi);
        Eke = BCe ^ ((~BCi) & BCo);
        Eki = BCi ^ ((~BCo) & BCu);
        Eko = BCo ^ ((~BCu) & BCa);
        Eku = BCu ^ ((~BCa) & BCe);

        Abu ^= Du;
        BCa = ROL(Abu, 27);
        Aga ^= Da;
        BCe = ROL(Aga, 36);
        Ake ^= De;
        BCi = ROL(Ake, 10);
        Ami ^= Di;
        BCo = ROL(Ami, 15);
        Aso ^= Do;
        BCu = ROL(Aso, 56);
        Ema = BCa ^ ((~BCe) & BCi);
        Eme = BCe ^ ((~BCi) & BCo);
        Emi = BCi ^ ((~BCo) & BCu);
        Emo = BCo ^ ((~BCu) & BCa);
        Emu = BCu ^ ((~BCa) & BCe);

        Abi ^= Di;
        BCa = ROL(Abi, 62);
        Ago ^= Do;
        BCe = ROL(Ago, 55);
        Aku ^= Du;
        BCi = ROL(Aku, 39);
        Ama ^= Da;
        BCo = ROL(Ama, 41);
        Ase ^= De;
        BCu = ROL(Ase, 2);
        Esa = BCa ^ ((~BCe) & BCi);
        Ese = BCe ^ ((~BCi) & BCo);
        Esi = BCi ^ ((~BCo) & BCu);
        Eso = BCo ^ ((~BCu) & BCa);
        Esu = BCu ^ ((~BCa) & BCe);

        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = ROL(Ege, 44);
        Eki ^= Di;
        BCi = ROL(Eki, 43);
        Emo ^= Do;
        BCo = ROL(Emo, 21);
        Esu ^= Du;
        BCu = ROL(Esu, 14);
        Aba = BCa ^ ((~BCe) & BCi);
        Aba ^= KeccakF_RoundConstants[round + 1];
        Abe = BCe ^ ((~BCi) & BCo);
        Abi = BCi ^ ((~BCo) & BCu);
        Abo = BCo ^ ((~BCu) & BCa);
        Abu = BCu ^ ((~BCa) & BCe);

        Ebo ^= Do;
        BCa = ROL(Ebo, 28);
        Egu ^= Du;
        BCe = ROL(Egu, 20);
        Eka ^= Da;
        BCi = ROL(Eka, 3);
        Eme ^= De;
        BCo = ROL(Eme, 45);
        Esi ^= Di;
        BCu = ROL(Esi, 61);
        Aga = BCa ^ ((~BCe) & BCi);
        Age = BCe ^ ((~BCi) & BCo);
        Agi = BCi ^ ((~BCo) & BCu);
        Ago = BCo ^ ((~BCu) & BCa);
        Agu = BCu ^ ((~BCa) & BCe);

        Ebe ^= De;
        BCa = ROL(Ebe, 1);
        Egi ^= Di;
        BCe = ROL(Egi, 6);
        Eko ^= Do;
        BCi = ROL(Eko, 25);
        Emu ^= Du;
        BCo = ROL(Emu, 8);
        Esa ^= Da;
        BCu = ROL(Esa, 18);
        Aka = BCa ^ ((~BCe) & BCi);
        Ake = BCe ^ ((~BCi) & BCo);
        Aki = BCi ^ ((~BCo) & BCu);
        Ako = BCo ^ ((~BCu) & BCa);
        Aku = BCu ^ ((~BCa) & BCe);

        Ebu ^= Du;
        BCa = ROL(Ebu, 27);
        Ega ^= Da;
        BCe = ROL(Ega, 36);
        Eke ^= De;
        BCi = ROL(Eke, 10);
        Emi ^= Di;
        BCo = ROL(Emi, 15);
        Eso ^= Do;
        BCu = ROL(Eso, 56);
        Ama = BCa ^ ((~BCe) & BCi);
        Ame = BCe ^ ((~BCi) & BCo);
        Ami = BCi ^ ((~BCo) & BCu);
        Amo = BCo ^ ((~BCu) & BCa);
        Amu = BCu ^ ((~BCa) & BCe);

        Ebi ^= Di;
        BCa = ROL(Ebi, 62);
        Ego ^= Do;
        BCe = ROL(Ego, 55);
        Eku ^= Du;
        BCi = ROL(Eku, 39);
        Ema ^= Da;
        BCo = ROL(Ema, 41);
        Ese ^= De;
        BCu = ROL(Ese, 2);
        Asa = BCa ^ ((~BCe) & BCi);
        Ase = BCe ^ ((~BCi) & BCo);
        Asi = BCi ^ ((~BCo) & BCu);
        Aso = BCo ^ ((~BCu) & BCa);
        Asu = BCu ^ ((~BCa) & BCe);
    }

    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}

/*************************************************
 * Name:        keccak_absorb
 *
 * Description: Absorb step of Keccak;
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - FIPS202_UINT64 *s: pointer to (uninitialized) output Keccak
 * state
 *              - FIPS202_UINT32 r: rate in bytes (e.g., 168 for SHAKE128)
 *              - const FIPS202_UINT8 *m: pointer to input to be absorbed into s
 *              - FIPS202_SIZE_T mlen: length of input in bytes
 *              - FIPS202_UINT8 p: domain-separation byte for different
 *                                 Keccak-derived functions
 **************************************************/
static void keccak_absorb(FIPS202_UINT64* s, FIPS202_UINT32 r,
                          const FIPS202_UINT8* m, FIPS202_SIZE_T mlen,
                          FIPS202_UINT8 p) {
    FIPS202_SIZE_T i;
    FIPS202_UINT8 t[200];

    /* Zero state */
    __builtin_memset(s, 0, 25 * sizeof(FIPS202_UINT64));

    while (mlen >= r) {
        for (i = 0; i < r / 8; ++i) {
            s[i] ^= load64(m + 8 * i);
        }

        KeccakF1600_StatePermute(s);
        mlen -= r;
        m += r;
    }

    __builtin_memset(t, 0, r);
    __builtin_memcpy(t, m, mlen);
    t[mlen] = p;

    t[r - 1] |= 128;
    for (i = 0; i < r / 8; ++i) {
        s[i] ^= load64(t + 8 * i);
    }
}

/*************************************************
 * Name:        keccak_squeezeblocks
 *
 * Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
 *              Modifies the state. Can be called multiple times to keep
 *              squeezing, i.e., is incremental.
 *
 * Arguments:   - FIPS202_UINT8 *h: pointer to output blocks
 *              - FIPS202_SIZE_T nblocks: number of blocks to be
 *                                                squeezed (written to h)
 *              - FIPS202_UINT64 *s: pointer to input/output Keccak state
 *              - FIPS202_UINT32 r: rate in bytes (e.g., 168 for SHAKE128)
 **************************************************/
static void keccak_squeezeblocks(FIPS202_UINT8* h, FIPS202_SIZE_T nblocks,
                                 FIPS202_UINT64* s, FIPS202_UINT32 r) {
    while (nblocks > 0) {
        KeccakF1600_StatePermute(s);
#pragma GCC unroll 21
        for (FIPS202_SIZE_T i = 0; i < (r >> 3); i++) {
            store64(h + 8 * i, s[i]);
        }
        h += r;
        nblocks--;
    }
}

/*************************************************
 * Name:        keccak_inc_init
 *
 * Description: Initializes the incremental Keccak state to zero.
 *
 * Arguments:   - FIPS202_UINT64 *s_inc: pointer to input/output incremental
 * state First 25 values represent Keccak state. 26th value represents either
 * the number of absorbed bytes that have not been permuted, or not-yet-squeezed
 * bytes.
 **************************************************/
static void keccak_inc_init(FIPS202_UINT64* s_inc) {
    __builtin_memset(s_inc, 0, 26 * sizeof(FIPS202_UINT64));
}

/*************************************************
 * Name:        keccak_inc_absorb
 *
 * Description: Incremental keccak absorb
 *              Preceded by keccak_inc_init, succeeded by keccak_inc_finalize
 *
 * Arguments:   - FIPS202_UINT64 *s_inc: pointer to input/output incremental
 * state First 25 values represent Keccak state. 26th value represents either
 * the number of absorbed bytes that have not been permuted, or not-yet-squeezed
 * bytes.
 *              - FIPS202_UINT32 r: rate in bytes (e.g., 168 for SHAKE128)
 *              - const FIPS202_UINT8 *m: pointer to input to be absorbed into s
 *              - FIPS202_SIZE_T mlen: length of input in bytes
 **************************************************/
static void keccak_inc_absorb(FIPS202_UINT64* s_inc, FIPS202_UINT32 r,
                              const FIPS202_UINT8* m, FIPS202_SIZE_T mlen) {
    FIPS202_SIZE_T i;

    /* Recall that s_inc[25] is the non-absorbed bytes xored into the state */
    while (mlen + s_inc[25] >= r) {
        for (i = 0; i < r - s_inc[25]; i++) {
            /* Take the i'th byte from message
               xor with the s_inc[25] + i'th byte of the state; little-endian */
            s_inc[(s_inc[25] + i) >> 3] ^= (FIPS202_UINT64)m[i]
                                           << (8 * ((s_inc[25] + i) & 0x07));
        }
        mlen -= (FIPS202_SIZE_T)(r - s_inc[25]);
        m += r - s_inc[25];
        s_inc[25] = 0;

        KeccakF1600_StatePermute(s_inc);
    }

    for (i = 0; i < mlen; i++) {
        s_inc[(s_inc[25] + i) >> 3] ^= (FIPS202_UINT64)m[i]
                                       << (8 * ((s_inc[25] + i) & 0x07));
    }
    s_inc[25] += mlen;
}

/*************************************************
 * Name:        keccak_inc_finalize
 *
 * Description: Finalizes Keccak absorb phase, prepares for squeezing
 *
 * Arguments:   - FIPS202_UINT64 *s_inc: pointer to input/output incremental
 * state First 25 values represent Keccak state. 26th value represents either
 * the number of absorbed bytes that have not been permuted, or not-yet-squeezed
 * bytes.
 *              - FIPS202_UINT32 r: rate in bytes (e.g., 168 for SHAKE128)
 *              - FIPS202_UINT8 p: domain-separation byte for different
 *                                 Keccak-derived functions
 **************************************************/
static void keccak_inc_finalize(FIPS202_UINT64* s_inc, FIPS202_UINT32 r,
                                FIPS202_UINT8 p) {
    /* After keccak_inc_absorb, we are guaranteed that s_inc[25] < r,
       so we can always use one more byte for p in the current state. */
    s_inc[s_inc[25] >> 3] ^= (FIPS202_UINT64)p << (8 * (s_inc[25] & 0x07));
    s_inc[(r - 1) >> 3] ^= (FIPS202_UINT64)128 << (8 * ((r - 1) & 0x07));
    s_inc[25] = 0;
}

/*************************************************
 * Name:        keccak_inc_squeeze
 *
 * Description: Incremental Keccak squeeze; can be called on byte-level
 *
 * Arguments:   - FIPS202_UINT8 *h: pointer to output bytes
 *              - FIPS202_SIZE_T outlen: number of bytes to be squeezed
 *              - FIPS202_UINT64 *s_inc: pointer to input/output incremental
 * state First 25 values represent Keccak state. 26th value represents either
 * the number of absorbed bytes that have not been permuted, or not-yet-squeezed
 * bytes.
 *              - FIPS202_UINT32 r: rate in bytes (e.g., 168 for SHAKE128)
 **************************************************/
static void keccak_inc_squeeze(FIPS202_UINT8* h, FIPS202_SIZE_T outlen,
                               FIPS202_UINT64* s_inc, FIPS202_UINT32 r) {
    FIPS202_SIZE_T i;

    /* First consume any bytes we still have sitting around */
    for (i = 0; i < outlen && i < s_inc[25]; i++) {
        /* There are s_inc[25] bytes left, so r - s_inc[25] is the first
           available byte. We consume from there, i.e., up to r. */
        h[i] = (FIPS202_UINT8)(s_inc[(r - s_inc[25] + i) >> 3] >>
                               (8 * ((r - s_inc[25] + i) & 0x07)));
    }
    h += i;
    outlen -= i;
    s_inc[25] -= i;

    /* Then squeeze the remaining necessary blocks */
    while (outlen > 0) {
        KeccakF1600_StatePermute(s_inc);

        for (i = 0; i < outlen && i < r; i++) {
            h[i] = (FIPS202_UINT8)(s_inc[i >> 3] >> (8 * (i & 0x07)));
        }
        h += i;
        outlen -= i;
        s_inc[25] = r - i;
    }
}

void shake128_inc_init(FIPS202_UINT64* s_inc) { keccak_inc_init(s_inc); }

void shake128_inc_absorb(FIPS202_UINT64* s_inc, const FIPS202_UINT8* input,
                         FIPS202_SIZE_T inlen) {
    keccak_inc_absorb(s_inc, SHAKE128_RATE, input, inlen);
}

void shake128_inc_finalize(FIPS202_UINT64* s_inc) {
    keccak_inc_finalize(s_inc, SHAKE128_RATE, 0x1F);
}

void shake128_inc_squeeze(FIPS202_UINT8* output, FIPS202_SIZE_T outlen,
                          FIPS202_UINT64* s_inc) {
    keccak_inc_squeeze(output, outlen, s_inc, SHAKE128_RATE);
}

/*************************************************
 * Name:        shake128_absorb
 *
 * Description: Absorb step of the SHAKE128 XOF.
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - FIPS202_UINT64 *s: pointer to (uninitialized) output Keccak
 * state
 *              - const FIPS202_UINT8 *input: pointer to input to be absorbed
 *                                            into s
 *              - FIPS202_SIZE_T inlen: length of input in bytes
 **************************************************/
void shake128_absorb(FIPS202_UINT64* s, const FIPS202_UINT8* input,
                     FIPS202_SIZE_T inlen) {
    keccak_absorb(s, SHAKE128_RATE, input, inlen, 0x1F);
}

/*************************************************
 * Name:        shake128_squeezeblocks
 *
 * Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
 *              SHAKE128_RATE bytes each. Modifies the state. Can be called
 *              multiple times to keep squeezing, i.e., is incremental.
 *
 * Arguments:   - FIPS202_UINT8 *output: pointer to output blocks
 *              - FIPS202_SIZE_T nblocks: number of blocks to be squeezed
 *                                (written to output)
 *              - FIPS202_UINT64 *s: pointer to input/output Keccak state
 **************************************************/
void shake128_squeezeblocks(FIPS202_UINT8* output, FIPS202_SIZE_T nblocks,
                            FIPS202_UINT64* s) {
    keccak_squeezeblocks(output, nblocks, s, SHAKE128_RATE);
}

/*************************************************
 * Name:        shake128
 *
 * Description: SHAKE128 XOF with non-incremental API
 *
 * Arguments:   - FIPS202_UINT8 *output: pointer to output
 *              - FIPS202_SIZE_T outlen: requested output length in bytes
 *              - const FIPS202_UINT8 *input: pointer to input
 *              - FIPS202_SIZE_T inlen: length of input in bytes
 **************************************************/
void shake128(FIPS202_UINT8* output, FIPS202_SIZE_T outlen,
              const FIPS202_UINT8* input, FIPS202_SIZE_T inlen) {
    FIPS202_SIZE_T nblocks = outlen / SHAKE128_RATE;
    FIPS202_UINT8 t[SHAKE128_RATE];
    FIPS202_UINT64 s[25];

    shake128_absorb(s, input, inlen);
    shake128_squeezeblocks(output, nblocks, s);

    output += nblocks * SHAKE128_RATE;
    outlen -= nblocks * SHAKE128_RATE;

    if (outlen) {
        shake128_squeezeblocks(t, 1, s);
        __builtin_memcpy(output, t, outlen);
    }
}

void shake256_inc_init(FIPS202_UINT64* s_inc) { keccak_inc_init(s_inc); }

void shake256_inc_absorb(FIPS202_UINT64* s_inc, const FIPS202_UINT8* input,
                         FIPS202_SIZE_T inlen) {
    keccak_inc_absorb(s_inc, SHAKE256_RATE, input, inlen);
}

void shake256_inc_finalize(FIPS202_UINT64* s_inc) {
    keccak_inc_finalize(s_inc, SHAKE256_RATE, 0x1F);
}

void shake256_inc_squeeze(FIPS202_UINT8* output, FIPS202_SIZE_T outlen,
                          FIPS202_UINT64* s_inc) {
    keccak_inc_squeeze(output, outlen, s_inc, SHAKE256_RATE);
}

/*************************************************
 * Name:        shake256_absorb
 *
 * Description: Absorb step of the SHAKE256 XOF.
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - FIPS202_UINT64 *s: pointer to (uninitialized) output Keccak
 * state
 *              - const FIPS202_UINT8 *input: pointer to input to be absorbed
 *                                            into s
 *              - FIPS202_SIZE_T inlen: length of input in bytes
 **************************************************/
void shake256_absorb(FIPS202_UINT64* s, const FIPS202_UINT8* input,
                     FIPS202_SIZE_T inlen) {
    keccak_absorb(s, SHAKE256_RATE, input, inlen, 0x1F);
}

/*************************************************
 * Name:        shake256_squeezeblocks
 *
 * Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
 *              SHAKE256_RATE bytes each. Modifies the state. Can be called
 *              multiple times to keep squeezing, i.e., is incremental.
 *
 * Arguments:   - FIPS202_UINT8 *output: pointer to output blocks
 *              - FIPS202_SIZE_T nblocks: number of blocks to be squeezed
 *                                (written to output)
 *              - FIPS202_UINT64 *s: pointer to input/output Keccak state
 **************************************************/
void shake256_squeezeblocks(FIPS202_UINT8* output, FIPS202_SIZE_T nblocks,
                            FIPS202_UINT64* s) {
    keccak_squeezeblocks(output, nblocks, s, SHAKE256_RATE);
}

/*************************************************
 * Name:        shake256
 *
 * Description: SHAKE256 XOF with non-incremental API
 *
 * Arguments:   - FIPS202_UINT8 *output: pointer to output
 *              - FIPS202_SIZE_T outlen: requested output length in bytes
 *              - const FIPS202_UINT8 *input: pointer to input
 *              - FIPS202_SIZE_T inlen: length of input in bytes
 **************************************************/
void shake256(FIPS202_UINT8* output, FIPS202_SIZE_T outlen,
              const FIPS202_UINT8* input, FIPS202_SIZE_T inlen) {
    FIPS202_SIZE_T nblocks = outlen / SHAKE256_RATE;
    FIPS202_UINT8 t[SHAKE256_RATE];
    FIPS202_UINT64 s[25];

    shake256_absorb(s, input, inlen);
    shake256_squeezeblocks(output, nblocks, s);

    output += nblocks * SHAKE256_RATE;
    outlen -= nblocks * SHAKE256_RATE;

    if (outlen) {
        shake256_squeezeblocks(t, 1, s);
        __builtin_memcpy(output, t, outlen);
    }
}

void sha3_256_inc_init(FIPS202_UINT64* s_inc) { keccak_inc_init(s_inc); }

void sha3_256_inc_absorb(FIPS202_UINT64* s_inc, const FIPS202_UINT8* input,
                         FIPS202_SIZE_T inlen) {
    keccak_inc_absorb(s_inc, SHA3_256_RATE, input, inlen);
}

void sha3_256_inc_finalize(FIPS202_UINT8* output, FIPS202_UINT64* s_inc) {
    FIPS202_UINT8 t[SHA3_256_RATE];
    keccak_inc_finalize(s_inc, SHA3_256_RATE, 0x06);
    KeccakF1600_StatePermute(s_inc);
    for (FIPS202_SIZE_T i = 0; i < 32; i++) {
        t[i] = (FIPS202_UINT8)(s_inc[i >> 3] >> (8 * (i & 0x07)));
    }
    __builtin_memcpy(output, t, 32);
}

/*************************************************
 * Name:        sha3_256
 *
 * Description: SHA3-256 with non-incremental API
 *
 * Arguments:   - FIPS202_UINT8 *output: pointer to output (32 bytes)
 *              - const FIPS202_UINT8 *input: pointer to input
 *              - FIPS202_SIZE_T inlen: length of input in bytes
 **************************************************/
void sha3_256(FIPS202_UINT8* output, const FIPS202_UINT8* input,
              FIPS202_SIZE_T inlen) {
    FIPS202_UINT64 s[25];
    FIPS202_UINT8 t[SHA3_256_RATE];

    keccak_absorb(s, SHA3_256_RATE, input, inlen, 0x06);
    KeccakF1600_StatePermute(s);
    for (FIPS202_SIZE_T i = 0; i < 32; i++) {
        t[i] = (FIPS202_UINT8)(s[i >> 3] >> (8 * (i & 0x07)));
    }
    __builtin_memcpy(output, t, 32);
}

void sha3_512_inc_init(FIPS202_UINT64* s_inc) { keccak_inc_init(s_inc); }

void sha3_512_inc_absorb(FIPS202_UINT64* s_inc, const FIPS202_UINT8* input,
                         FIPS202_SIZE_T inlen) {
    keccak_inc_absorb(s_inc, SHA3_512_RATE, input, inlen);
}

void sha3_512_inc_finalize(FIPS202_UINT8* output, FIPS202_UINT64* s_inc) {
    FIPS202_UINT8 t[SHA3_512_RATE];
    keccak_inc_finalize(s_inc, SHA3_512_RATE, 0x06);
    KeccakF1600_StatePermute(s_inc);
    for (FIPS202_SIZE_T i = 0; i < 64; i++) {
        t[i] = (FIPS202_UINT8)(s_inc[i >> 3] >> (8 * (i & 0x07)));
    }
    __builtin_memcpy(output, t, 64);
}

/*************************************************
 * Name:        sha3_512
 *
 * Description: SHA3-512 with non-incremental API
 *
 * Arguments:   - FIPS202_UINT8 *output: pointer to output (64 bytes)
 *              - const FIPS202_UINT8 *input: pointer to input
 *              - FIPS202_SIZE_T inlen: length of input in bytes
 **************************************************/
void sha3_512(FIPS202_UINT8* output, const FIPS202_UINT8* input,
              FIPS202_SIZE_T inlen) {
    FIPS202_UINT64 s[25];
    FIPS202_UINT8 t[SHA3_512_RATE];

    keccak_absorb(s, SHA3_512_RATE, input, inlen, 0x06);
    KeccakF1600_StatePermute(s);
    for (FIPS202_SIZE_T i = 0; i < 64; i++) {
        t[i] = (FIPS202_UINT8)(s[i >> 3] >> (8 * (i & 0x07)));
    }
    __builtin_memcpy(output, t, 64);
}
