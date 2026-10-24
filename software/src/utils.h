#ifndef __UTILS_H_
#define __UTILS_H_

#include <Arduino.h>
#include <string>

// Hex and Base58 utilities
String toHex(const uint8_t* data, size_t len);
String toBase58(const uint8_t* data, size_t len);
size_t fromHex(const char* hex, uint8_t* data, size_t maxLen);

// Crypto utilities
void sha256(const uint8_t* data, size_t len, uint8_t* output);

#endif
