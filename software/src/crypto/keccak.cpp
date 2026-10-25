#include "keccak.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* Keccak-f[1600] permutation                                         */
/* ------------------------------------------------------------------ */

#define KECCAK_ROUNDS 24

/* Round constants (Keccak) */
static const uint64_t KECCAK_RC[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000008000ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000080008080ULL,
    0x0000000080000001ULL, 0x8000000080000008ULL,
};

/* Rotation offsets for each of the 24 steps (rho) */
static const unsigned KECCAK_RHO[KECCAK_ROUNDS] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44,
};

/* Permutation of lane indices (pi) */
static const unsigned KECCAK_PI[KECCAK_ROUNDS] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1,
};

static inline uint64_t rotl64(uint64_t x, unsigned n) {
    return (x << n) | (x >> (64 - n));
}

static inline uint64_t load64le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

static inline void store64le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

/* Keccak-f[1600] permutation on a 25-lane state (each lane 64 bits) */
static void keccak_f1600(uint64_t st[25]) {
    uint64_t C[5], D[5];
    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        /* Theta */
        for (int x = 0; x < 5; x++) {
            C[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        }
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (int y = 0; y < 25; y += 5) {
            for (int x = 0; x < 5; x++) {
                st[y + x] ^= D[x];
            }
        }

        /* Rho + Pi */
        uint64_t t = st[1];
        for (int i = 0; i < KECCAK_ROUNDS; i++) {
            unsigned j = KECCAK_PI[i];
            uint64_t tmp = st[j];
            st[j] = rotl64(t, KECCAK_RHO[i]);
            t = tmp;
        }

        /* Chi */
        uint64_t B[5];
        for (int y = 0; y < 25; y += 5) {
            for (int x = 0; x < 5; x++) {
                B[x] = st[y + x];
            }
            for (int x = 0; x < 5; x++) {
                st[y + x] = B[x] ^ ((~B[(x + 1) % 5]) & B[(x + 2) % 5]);
            }
        }

        /* Iota */
        st[0] ^= KECCAK_RC[round];
    }
}

/* ------------------------------------------------------------------ */
/* Keccak sponge                                                      */
/* ------------------------------------------------------------------ */

/* Rate in bytes for Keccak-256: (1600 - 2*256) / 8 = 136 bytes */
#define KECCAK256_RATE_BYTES 136

void keccak256(uint8_t out[32], const uint8_t *in, size_t inlen) {
    uint64_t st[25];
    memset(st, 0, sizeof(st));

    /* Absorb whole blocks */
    while (inlen >= KECCAK256_RATE_BYTES) {
        for (int i = 0; i < KECCAK256_RATE_BYTES / 8; i++) {
            st[i] ^= load64le(in + 8 * i);
        }
        keccak_f1600(st);
        in += KECCAK256_RATE_BYTES;
        inlen -= KECCAK256_RATE_BYTES;
    }

    /* Absorb the final (partial) block with Ethereum/Keccak 0x01 padding */
    uint8_t block[KECCAK256_RATE_BYTES];
    memset(block, 0, sizeof(block));
    memcpy(block, in, inlen);
    block[inlen] ^= 0x01;               /* domain separation byte */
    block[KECCAK256_RATE_BYTES - 1] ^= 0x80; /* final bit */
    for (int i = 0; i < KECCAK256_RATE_BYTES / 8; i++) {
        st[i] ^= load64le(block + 8 * i);
    }
    keccak_f1600(st);

    /* Squeeze the first 32 bytes (4 lanes) of the state */
    for (int i = 0; i < 4; i++) {
        store64le(out + 8 * i, st[i]);
    }
}
