#ifndef KEY_H
#define KEY_H

#include <stdint.h>
#include <array>

enum WalletNetwork {
    BTC,
    ETH,
    U2F
};

class Key {
public:
    Key() : network(BTC), id(0), nonce(0) {}

    WalletNetwork network;
    uint8_t id;
    uint32_t nonce;
    std::array<uint8_t, 32> privateKey;  // PIN-encrypted private key scalar
    std::array<uint8_t, 33> publicKey;   // compressed SEC bytes of the public key
};

// BIP32 root of the wallet, so BIP84 (native SegWit) accounts and PSBT
// signing can derive any key. Only the root is secret (PIN-encrypted);
// the account xpubs let the device show addresses without the PIN.
#define HD_RECORD_MAGIC 0x31444853UL   // "SHD1"
#define HD_XPUB_LEN     112            // base58 xpub/tpub, NUL-terminated

struct HdRecord {
    uint32_t magic;
    uint8_t  encRoot[64];             // (root secret | chain code) XOR keystream(PIN)
    uint8_t  fingerprint[4];          // master key fingerprint
    char     xpub[2][HD_XPUB_LEN];    // m/84'/0'/0' (xpub) and m/84'/1'/0' (tpub)
};

#endif // KEY_H