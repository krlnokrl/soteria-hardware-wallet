#ifndef KEY_H
#define KEY_H

#include <stdint.h>

// Public part of the wallet, in the EEPROM. The secret BIP32 root is
// sealed in the ATECC508A (src/se/se_wallet.h); everything here can be
// shown without the PIN.
#define HD_RECORD_MAGIC 0x32444853UL   // "SHD2"
#define HD_XPUB_LEN     112            // base58 xpub/tpub, NUL-terminated

struct HdRecord {
    uint32_t magic;
    uint8_t  fingerprint[4];          // master key fingerprint
    char     xpub[2][HD_XPUB_LEN];    // m/84'/0'/0' (xpub) and m/84'/1'/0' (tpub)
    uint8_t  btcLegacy[33];           // compressed public keys of m/44'/0'/0'/0/0,
    uint8_t  btcTestLegacy[33];       // m/44'/1'/0'/0/0
    uint8_t  eth[33];                 // and m/44'/60'/0'/0/0
};

// Pairing with the ATECC508A secure element (src/se, docs/ATECC_PLAN.md).
// The pairing secret P authorises encrypted access to the chip's non-PIN
// slots (FIDO2 secret). It belongs to the device, not to a wallet: wallet
// erase keeps it, and it lives in the EEPROM because uploads erase flash.
#define SE_RECORD_MAGIC 0x31455353UL   // "SSE1"

struct SeRecord {
    uint32_t magic;
    uint8_t  serial[9];                // chip this secret belongs to
    uint8_t  rfu[3];
    uint8_t  pairing[32];
};

#endif // KEY_H
