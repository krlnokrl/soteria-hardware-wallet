#ifndef SE_WALLET_H
#define SE_WALLET_H

// Wallet secrets in the ATECC508A (docs/ATECC_PLAN.md, slot map in
// se_layout.h). No display, no Bitcoin code: the UI (wallet.cpp) asks for
// PIN/PUK and passes the digits in.
//
//   PIN (6 hex digits) -> s = SHA256(P | MAC^n(W, SHA256("soteria-pin" | SN | digits)))
//                         V = SHA256("soteria-V" | s)       PIN verifier, slot 2
//                         K = SHA256("soteria-K0"/"-K1" | s) MCU-side seed key
//   PUK (8 hex digits) -> M = SHA256("soteria-M" | s')      PUK verifier, slot 3
//
// The MAC rounds run inside the chip with W, which never leaves it, so
// every PIN guess costs chip time. The chip itself checks a PIN: an
// encrypted write with V (slot 12, last-good counter) only succeeds with
// the right V. The seed (slot 9) is sealed twice: XOR K, and the chip
// only releases it encrypted to someone who knows V.
#include "atecc.h"
#include <SecureStorage.h>

#define SE_PIN_DIGITS     6
#define SE_PUK_DIGITS     8
#define SE_ROOT_SIZE      64   // BIP32 root secret | chain code
#define SE_STRETCH_ROUNDS 48   // chip MAC rounds per PIN/PUK check

enum SeResult : uint8_t {
    SE_OK = 0,
    SE_WRONG_PIN,
    SE_WRONG_PUK,
    SE_NEED_PUK,     // the chip holds a PUK: a new wallet needs it
    SE_NOT_READY,    // chip not provisioned / not paired with this device
    SE_CHIP_ERROR,   // communication with the chip failed
};

const char *seResultText(SeResult r);

class SeWallet {
public:
    // Check the chip (locked with the planned slot map) and load the
    // pairing record from the EEPROM; ready() tells whether both match.
    bool begin(Atecc &chip, SecureStorage &eeprom);
    bool ready() const { return _ready; }
    const uint8_t *serial() const { return _sn; }

    // Random bytes: fresh chip RNG output and A0 noise through SHA-256.
    // False if the chip did not contribute (the output is then A0-only).
    bool random(uint8_t *out, size_t len);

    // New wallet. puk = the current PUK, or nullptr while the chip is in
    // factory state. A fresh PUK (digits 0-15) is returned in newPuk.
    SeResult create(const uint8_t pin[SE_PIN_DIGITS], const uint8_t root[SE_ROOT_SIZE],
                    const uint8_t fido[32], const uint8_t *puk, uint8_t newPuk[SE_PUK_DIGITS]);
    // Check the PIN on the chip and return the root. failed = wrong PIN
    // attempts since the last unlock (from the monotonic counter).
    SeResult unlock(const uint8_t pin[SE_PIN_DIGITS], uint8_t root[SE_ROOT_SIZE], uint32_t *failed);
    // Needs the old PIN (to unseal the root) and the PUK (to rewrite V).
    SeResult changePin(const uint8_t oldPin[SE_PIN_DIGITS], const uint8_t puk[SE_PUK_DIGITS],
                       const uint8_t newPin[SE_PIN_DIGITS]);
    // Erase the wallet (seed and FIDO2 secret). PIN and PUK stay valid.
    SeResult wipe(const uint8_t pin[SE_PIN_DIGITS]);
    // Back to factory state: wallet erased, PIN/PUK/W reset.
    SeResult factoryReset(const uint8_t puk[SE_PUK_DIGITS]);

    // FIDO2 master secret (no PIN needed); false if there is none.
    bool fidoSecret(uint8_t out[32]);
    // FIDO2 signature counter (chip counter 1).
    bool fidoCounter(uint32_t &value, bool increment);

private:
    SeResult pinKeys(const uint8_t pin[SE_PIN_DIGITS], uint8_t v[32], uint8_t k[SE_ROOT_SIZE]);
    SeResult pukKey(const uint8_t puk[SE_PUK_DIGITS], uint8_t m[32]);
    SeResult stretch(const char *label, const uint8_t *digits, uint8_t n, uint8_t s[32]);
    SeResult checkPin(const uint8_t v[32], uint32_t *failed);
    SeResult seal(const uint8_t v[32], const uint8_t k[SE_ROOT_SIZE], const uint8_t root[SE_ROOT_SIZE]);
    SeResult writeLastGood(const uint8_t v[32]);
    SeResult zeroWallet(const uint8_t v[32]);

    Atecc *_chip = nullptr;
    bool _ready = false;
    uint8_t _sn[9] = { 0 };
    uint8_t _pairing[32] = { 0 };
    uint8_t _pool[32] = { 0 };
    uint32_t _draws = 0;
};

#endif // SE_WALLET_H
