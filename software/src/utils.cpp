#include "utils.h"
#include "crypto/keccak.h"

// NOTE: toHex(), toBase58() and sha256() are provided by uBitcoin
// (included via <Bitcoin.h>), so they are intentionally NOT defined here
// to avoid multiple-definition linker errors.

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

void keccak256(const uint8_t* data, size_t len, uint8_t out[32]) {
    ::keccak256(out, data, len);
}

/* nibble to lowercase hex char */
static char nibbleToHex(uint8_t n) {
    return n < 10 ? char('0' + n) : char('a' + n - 10);
}

/* EIP-55 checksum: uppercase hex chars where corresponding keccak256 hash nibble >= 8 */
static void eip55Checksum(const char* addr40, const uint8_t hash[32], char out[43]) {
    out[0] = '0';
    out[1] = 'x';
    for (int i = 0; i < 40; i++) {
        char c = addr40[i];
        if (c >= 'a' && c <= 'f') {
            uint8_t hashNibble = hash[i / 2] >> (4 * (1 - (i % 2))) & 0x0F;
            if (hashNibble >= 8) {
                c = char(c - 'a' + 'A');  // uppercase
            }
        }
        out[2 + i] = c;
    }
    out[42] = 0;
}

size_t ethAddressFromPubkey(const uint8_t pubkey[65], char out[43]) {
    // out must be at least 43 bytes ("0x" + 40 hex + NUL)
    uint8_t hash[32];
    keccak256(pubkey + 1, 64, hash);          // Keccak-256 of x||y (uncompressed, without 0x04 prefix)

    uint8_t addr[20];
    memcpy(addr, hash + 12, 20);              // last 20 bytes of the hash

    char addr40[41];
    for (int i = 0; i < 20; i++) {
        addr40[2 * i] = nibbleToHex(addr[i] >> 4);
        addr40[2 * i + 1] = nibbleToHex(addr[i] & 0x0F);
    }
    addr40[40] = 0;

    eip55Checksum(addr40, hash, out);
    return 42;
}
