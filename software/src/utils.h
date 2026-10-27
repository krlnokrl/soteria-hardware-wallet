#ifndef __UTILS_H_
#define __UTILS_H_

#include <Arduino.h>
#include <string>
// sha256() and sha256Hmac() come from uBitcoin; include its declarations
// rather than re-declaring them with a different return type.
#include <Hash.h>

// Hex utilities (toHex/toBase58 are provided by uBitcoin via <Bitcoin.h>)
size_t fromHex(const char* hex, uint8_t* data, size_t maxLen);

// Keccak-256 (Ethereum flavour, 0x01 padding). Implemented in crypto/keccak.cpp.
void keccak256(const uint8_t* data, size_t len, uint8_t out[32]);

// Derive a checksummed Ethereum address (EIP-55) from an uncompressed public key
// (65 bytes: 0x04 || x || y). Writes a null-terminated 0x-prefixed address to `out`
// (out must be at least 43 bytes). Returns the length written.
size_t ethAddressFromPubkey(const uint8_t pubkey[65], char out[43]);

// Format a raw 20-byte Ethereum address as 0x-prefixed EIP-55 text.
size_t ethAddressToString(const uint8_t addr[20], char out[43]);

#endif
