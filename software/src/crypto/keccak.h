#ifndef SOTERIA_KECCAK_H
#define SOTERIA_KECCAK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Compute Keccak-256 (Ethereum flavour: 0x01 suffix padding) of `inlen` bytes
 * at `in`, writing the 32-byte digest to `out`.
 *
 * Implementation derived from keccak-tiny (coruus), public domain — a compact,
 * table-free, single-file Keccak-f[1600] permutation suitable for embedded
 * targets (SAMD21: ~1 KB flash, small stack).
 */
void keccak256(uint8_t out[32], const uint8_t *in, size_t inlen);

#ifdef __cplusplus
}
#endif

#endif // SOTERIA_KECCAK_H
