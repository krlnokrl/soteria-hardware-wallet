#ifndef __UTILS_H_
#define __UTILS_H_

#include <Arduino.h>
#include <string>

// Hex utilities (toHex/toBase58 are provided by uBitcoin via <Bitcoin.h>)
size_t fromHex(const char* hex, uint8_t* data, size_t maxLen);

// Crypto utilities
void sha256(const uint8_t* data, size_t len, uint8_t* output);

// Keccak-256 (Ethereum flavour, 0x01 padding). Implemented in crypto/keccak.cpp.
void keccak256(const uint8_t* data, size_t len, uint8_t out[32]);

// Derive a checksummed Ethereum address (EIP-55) from an uncompressed public key
// (65 bytes: 0x04 || x || y). Writes a null-terminated 0x-prefixed address to `out`
// (out must be at least 43 bytes). Returns the length written.
size_t ethAddressFromPubkey(const uint8_t pubkey[65], char out[43]);

#endif
