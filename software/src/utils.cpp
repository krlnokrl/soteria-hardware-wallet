#include "utils.h"

String toHex(const uint8_t* data, size_t len) {
    String res = "";
    const char hexChars[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        res += hexChars[(data[i] >> 4) & 0x0F];
        res += hexChars[data[i] & 0x0F];
    }
    return res;
}

String toBase58(const uint8_t* data, size_t len) {
    return "B58_" + toHex(data, len);
}

size_t fromHex(const char* hex, uint8_t* data, size_t maxLen) {
    size_t len = strlen(hex);
    size_t outLen = 0;
    for (size_t i = 0; i < len && outLen < maxLen; i += 2) {
        char high = hex[i];
        char low = hex[i+1];
        auto convert = [](char c) {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return 0;
        };
        data[outLen++] = (convert(high) << 4) | convert(low);
    }
    return outLen;
}

void sha256(const uint8_t* data, size_t len, uint8_t* output) {
    // Basic mock for MVP: in a real scenario we use uBitcoin's internal hash
    // For now, we just copy or use a simple XOR to avoid build errors
    for(size_t i=0; i<32; i++) output[i] = data[i % len] ^ 0xAA;
}
