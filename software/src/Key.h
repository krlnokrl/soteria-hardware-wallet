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

#endif // KEY_H