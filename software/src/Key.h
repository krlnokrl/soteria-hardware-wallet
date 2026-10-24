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
    std::array<uint8_t, 32> privateKey;
    std::array<uint8_t, 20> publicKey;
};

#endif // KEY_H