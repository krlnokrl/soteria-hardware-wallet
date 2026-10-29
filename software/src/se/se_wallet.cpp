#include "se_wallet.h"
#include "se_layout.h"
#include "se_keys.h"
#include <Hash.h>

// A0 noise (src/wallet.cpp; deterministic stand-in in the host tests)
int RNGpin(uint8_t *dest, unsigned size);

const char *seResultText(SeResult r) {
    switch (r) {
        case SE_OK:         return "ok";
        case SE_WRONG_PIN:  return "wrong PIN";
        case SE_WRONG_PUK:  return "wrong PUK";
        case SE_NEED_PUK:   return "PUK required";
        case SE_NOT_READY:  return "secure element not provisioned";
        case SE_CHIP_ERROR: return "secure element error";
        default:            return "?";
    }
}

// Bus/communication problems vs. the chip refusing a key.
static SeResult result(uint8_t st, SeResult refused) {
    if (st == ATECC_SUCCESS) return SE_OK;
    bool comm = st == ATECC_NO_DEVICE || st == ATECC_TIMEOUT || st == ATECC_BAD_RESPONSE ||
                st == ATECC_COMM_ERROR || st == ATECC_WATCHDOG || st == ATECC_AFTER_WAKE;
    return comm ? SE_CHIP_ERROR : refused;
}

static void tagged(const char *tag, const uint8_t s[32], uint8_t out[32]) {
    SHA256 h;
    h.write((const uint8_t *)tag, strlen(tag));
    h.write(s, 32);
    h.end(out);
}

static void putLe32(uint8_t block[32], uint32_t v) {
    memset(block, 0, 32);
    for (int i = 0; i < 4; i++) block[i] = (uint8_t)(v >> (8 * i));
}

// The chip's Random before the config lock: FF FF 00 00 repeated.
static bool fixedPattern(const uint8_t r[32]) {
    for (int i = 0; i < 32; i++) {
        if (r[i] != ((i & 3) < 2 ? 0xFF : 0x00)) return false;
    }
    return true;
}

static const uint8_t ZEROS[32] = { 0 };

/* ------------------------------------------------------------------ */
/* Setup and randomness                                                */
/* ------------------------------------------------------------------ */

bool SeWallet::begin(Atecc &chip, SecureStorage &eeprom) {
    _chip = &chip;
    _ready = false;
    uint8_t a0[32];
    RNGpin(a0, sizeof(a0));
    SHA256 h;
    h.write(_pool, sizeof(_pool));
    h.write(a0, sizeof(a0));
    h.end(_pool);
    chip.mixHostEntropy(a0, sizeof(a0));

    uint8_t cfg[ATECC_CONFIG_SIZE];
    if (chip.readConfig(cfg) != ATECC_SUCCESS) return false;
    if (!seConfigLocked(cfg) || !seDataLocked(cfg)) return false;
    for (int s = 0; s < SE_SLOTS; s++) {
        if (seSlotConfig(cfg, s) != SE_PLAN[s].slotConfig || seKeyConfig(cfg, s) != SE_PLAN[s].keyConfig) {
            return false;
        }
    }
    seSerial(cfg, _sn);
    SeRecord rec;
    if (!eeprom.readSe(rec) || memcmp(rec.serial, _sn, 9) != 0) return false;
    memcpy(_pairing, rec.pairing, 32);
    memset(&rec, 0, sizeof(rec));
    _ready = true;
    return true;
}

bool SeWallet::random(uint8_t *out, size_t len) {
    uint8_t chip[32], a0[4];
    bool fromChip = _chip && _chip->random(chip) == ATECC_SUCCESS && !fixedPattern(chip);
    RNGpin(a0, sizeof(a0));
    SHA256 h;
    h.write(_pool, sizeof(_pool));
    if (fromChip) h.write(chip, sizeof(chip));
    h.write(a0, sizeof(a0));
    h.write((const uint8_t *)&_draws, sizeof(_draws));
    h.end(_pool);
    _draws++;
    for (uint32_t i = 0; len; i++) {
        uint8_t block[32];
        SHA256 o;
        o.write(_pool, sizeof(_pool));
        o.write((const uint8_t *)"out", 3);
        o.write((const uint8_t *)&i, sizeof(i));
        o.end(block);
        size_t n = len < 32 ? len : 32;
        memcpy(out, block, n);
        out += n;
        len -= n;
    }
    tagged("next", _pool, _pool);   // outputs cannot be recomputed from a later pool
    memset(chip, 0, sizeof(chip));
    return fromChip;
}

/* ------------------------------------------------------------------ */
/* Key derivation                                                      */
/* ------------------------------------------------------------------ */

SeResult SeWallet::stretch(const char *label, const uint8_t *digits, uint8_t n, uint8_t s[32]) {
    uint8_t x[32];
    SHA256 h;
    h.write((const uint8_t *)label, strlen(label));
    h.write(_sn, sizeof(_sn));
    h.write(digits, n);
    h.end(x);
    uint8_t st = _chip->macChain(SE_SLOT_STRETCH, x, SE_STRETCH_ROUNDS);
    if (st != ATECC_SUCCESS) return SE_CHIP_ERROR;
    // The last MAC crossed the bus in the clear: mix in the pairing secret.
    SHA256 f;
    f.write(_pairing, sizeof(_pairing));
    f.write(x, sizeof(x));
    f.end(s);
    memset(x, 0, sizeof(x));
    return SE_OK;
}

SeResult SeWallet::pinKeys(const uint8_t pin[SE_PIN_DIGITS], uint8_t v[32], uint8_t k[SE_ROOT_SIZE]) {
    uint8_t s[32];
    SeResult r = stretch("soteria-pin", pin, SE_PIN_DIGITS, s);
    if (r != SE_OK) return r;
    tagged("soteria-V", s, v);
    tagged("soteria-K0", s, k);
    tagged("soteria-K1", s, k + 32);
    memset(s, 0, sizeof(s));
    return SE_OK;
}

SeResult SeWallet::pukKey(const uint8_t puk[SE_PUK_DIGITS], uint8_t m[32]) {
    uint8_t s[32];
    SeResult r = stretch("soteria-puk", puk, SE_PUK_DIGITS, s);
    if (r != SE_OK) return r;
    tagged("soteria-M", s, m);
    memset(s, 0, sizeof(s));
    return SE_OK;
}

/* ------------------------------------------------------------------ */
/* Slot helpers                                                        */
/* ------------------------------------------------------------------ */

// The chip checks the PIN: only the right V can write the last-good
// counter (slot 12). The attempt counter goes up before the check.
SeResult SeWallet::checkPin(const uint8_t v[32], uint32_t *failed) {
    uint8_t block[32];
    if (_chip->read32(SE_SLOT_PIN_COUNT, 0, block) != ATECC_SUCCESS) return SE_CHIP_ERROR;
    uint32_t last = (uint32_t)block[0] | block[1] << 8 | block[2] << 16 | (uint32_t)block[3] << 24;
    uint32_t now;
    if (_chip->counter(0, true, now) != ATECC_SUCCESS) return SE_CHIP_ERROR;
    putLe32(block, now);
    SeResult r = result(_chip->writeEncrypted(SE_SLOT_PIN_COUNT, 0, SE_SLOT_PIN, v, block), SE_WRONG_PIN);
    if (r == SE_OK && failed) *failed = now > last ? now - last - 1 : 0;
    return r;
}

SeResult SeWallet::writeLastGood(const uint8_t v[32]) {
    uint32_t now;
    if (_chip->counter(0, false, now) != ATECC_SUCCESS) return SE_CHIP_ERROR;
    uint8_t block[32];
    putLe32(block, now);
    return result(_chip->writeEncrypted(SE_SLOT_PIN_COUNT, 0, SE_SLOT_PIN, v, block), SE_WRONG_PIN);
}

SeResult SeWallet::seal(const uint8_t v[32], const uint8_t k[SE_ROOT_SIZE], const uint8_t root[SE_ROOT_SIZE]) {
    for (uint8_t b = 0; b < SE_ROOT_SIZE / 32; b++) {
        uint8_t block[32];
        for (int i = 0; i < 32; i++) block[i] = root[32 * b + i] ^ k[32 * b + i];
        SeResult r = result(_chip->writeEncrypted(SE_SLOT_SEED, b, SE_SLOT_PIN, v, block), SE_WRONG_PIN);
        memset(block, 0, sizeof(block));
        if (r != SE_OK) return r;
    }
    return SE_OK;
}

SeResult SeWallet::zeroWallet(const uint8_t v[32]) {
    const uint8_t seeds[] = { SE_SLOT_SEED, SE_SLOT_SPARE_SEED };
    for (uint8_t slot : seeds) {
        for (uint8_t b = 0; b < 2; b++) {
            SeResult r = result(_chip->writeEncrypted(slot, b, SE_SLOT_PIN, v, ZEROS), SE_WRONG_PIN);
            if (r != SE_OK) return r;
        }
    }
    return result(_chip->writeEncrypted(SE_SLOT_FIDO, 0, SE_SLOT_PAIRING, _pairing, ZEROS), SE_CHIP_ERROR);
}

/* ------------------------------------------------------------------ */
/* Wallet operations                                                   */
/* ------------------------------------------------------------------ */

SeResult SeWallet::create(const uint8_t pin[SE_PIN_DIGITS], const uint8_t root[SE_ROOT_SIZE],
                          const uint8_t fido[32], const uint8_t *puk, uint8_t newPuk[SE_PUK_DIGITS]) {
    if (!_ready) return SE_NOT_READY;
    uint8_t m[32], v[32], k[SE_ROOT_SIZE], mNew[32];
    SeResult r = puk ? pukKey(puk, m) : SE_OK;
    if (!puk) seFactoryPuk(_sn, m);
    if (r == SE_OK) r = pinKeys(pin, v, k);
    // The PUK (or the factory value) authorises the new PIN verifier.
    if (r == SE_OK) {
        r = result(_chip->writeEncrypted(SE_SLOT_PIN, 0, SE_SLOT_PUK, m, v), puk ? SE_WRONG_PUK : SE_NEED_PUK);
    }
    if (r == SE_OK) r = writeLastGood(v);
    if (r == SE_OK) r = seal(v, k, root);
    if (r == SE_OK) {
        r = result(_chip->writeEncrypted(SE_SLOT_FIDO, 0, SE_SLOT_PAIRING, _pairing, fido), SE_CHIP_ERROR);
    }
    // The new PUK last: until then the old one (or factory) still works.
    if (r == SE_OK) {
        uint8_t rnd[SE_PUK_DIGITS / 2];
        random(rnd, sizeof(rnd));
        for (int i = 0; i < SE_PUK_DIGITS; i++) newPuk[i] = (rnd[i / 2] >> (i & 1 ? 0 : 4)) & 0x0F;
        r = pukKey(newPuk, mNew);
    }
    if (r == SE_OK) r = result(_chip->writeEncrypted(SE_SLOT_PUK, 0, SE_SLOT_PUK, m, mNew), SE_CHIP_ERROR);
    memset(m, 0, sizeof(m));
    memset(v, 0, sizeof(v));
    memset(k, 0, sizeof(k));
    memset(mNew, 0, sizeof(mNew));
    return r;
}

SeResult SeWallet::unlock(const uint8_t pin[SE_PIN_DIGITS], uint8_t root[SE_ROOT_SIZE], uint32_t *failed) {
    if (!_ready) return SE_NOT_READY;
    uint8_t v[32], k[SE_ROOT_SIZE];
    SeResult r = pinKeys(pin, v, k);
    if (r == SE_OK) r = checkPin(v, failed);
    for (uint8_t b = 0; b < SE_ROOT_SIZE / 32 && r == SE_OK; b++) {
        uint8_t st = _chip->readEncrypted(SE_SLOT_SEED, b, SE_SLOT_PIN, v, root + 32 * b);
        r = result(st, SE_CHIP_ERROR);
        for (int i = 0; i < 32 && r == SE_OK; i++) root[32 * b + i] ^= k[32 * b + i];
    }
    if (r != SE_OK) memset(root, 0, SE_ROOT_SIZE);
    memset(v, 0, sizeof(v));
    memset(k, 0, sizeof(k));
    return r;
}

SeResult SeWallet::changePin(const uint8_t oldPin[SE_PIN_DIGITS], const uint8_t puk[SE_PUK_DIGITS],
                             const uint8_t newPin[SE_PIN_DIGITS]) {
    uint8_t root[SE_ROOT_SIZE], m[32], v[32], k[SE_ROOT_SIZE];
    SeResult r = unlock(oldPin, root, nullptr);
    if (r == SE_OK) r = pukKey(puk, m);
    if (r == SE_OK) r = pinKeys(newPin, v, k);
    if (r == SE_OK) r = result(_chip->writeEncrypted(SE_SLOT_PIN, 0, SE_SLOT_PUK, m, v), SE_WRONG_PUK);
    // From here the old PIN is gone: reseal the root for the new one.
    if (r == SE_OK) r = seal(v, k, root);
    if (r == SE_OK) r = writeLastGood(v);
    memset(root, 0, sizeof(root));
    memset(m, 0, sizeof(m));
    memset(v, 0, sizeof(v));
    memset(k, 0, sizeof(k));
    return r;
}

SeResult SeWallet::wipe(const uint8_t pin[SE_PIN_DIGITS]) {
    if (!_ready) return SE_NOT_READY;
    uint8_t v[32], k[SE_ROOT_SIZE];
    SeResult r = pinKeys(pin, v, k);
    if (r == SE_OK) r = checkPin(v, nullptr);
    if (r == SE_OK) r = zeroWallet(v);
    memset(v, 0, sizeof(v));
    memset(k, 0, sizeof(k));
    return r;
}

SeResult SeWallet::factoryReset(const uint8_t puk[SE_PUK_DIGITS]) {
    if (!_ready) return SE_NOT_READY;
    uint8_t m[32], v[32], mFactory[32], w[32];
    SeResult r = pukKey(puk, m);
    seFactoryPin(_sn, v);
    seFactoryPuk(_sn, mFactory);
    if (r == SE_OK) r = result(_chip->writeEncrypted(SE_SLOT_PIN, 0, SE_SLOT_PUK, m, v), SE_WRONG_PUK);
    if (r == SE_OK) r = zeroWallet(v);
    if (r == SE_OK) r = writeLastGood(v);
    // PUK back to factory before W changes: the user's PUK depends on W.
    if (r == SE_OK) r = result(_chip->writeEncrypted(SE_SLOT_PUK, 0, SE_SLOT_PUK, m, mFactory), SE_CHIP_ERROR);
    if (r == SE_OK) {
        random(w, sizeof(w));
        r = result(_chip->writeEncrypted(SE_SLOT_STRETCH, 0, SE_SLOT_PUK, mFactory, w), SE_CHIP_ERROR);
    }
    memset(m, 0, sizeof(m));
    memset(w, 0, sizeof(w));
    return r;
}

/* ------------------------------------------------------------------ */
/* FIDO2                                                               */
/* ------------------------------------------------------------------ */

bool SeWallet::fidoSecret(uint8_t out[32]) {
    if (!_ready) return false;
    if (_chip->readEncrypted(SE_SLOT_FIDO, 0, SE_SLOT_PAIRING, _pairing, out) != ATECC_SUCCESS) return false;
    return memcmp(out, ZEROS, 32) != 0;
}

bool SeWallet::fidoCounter(uint32_t &value, bool increment) {
    return _ready && _chip->counter(1, increment, value) == ATECC_SUCCESS;
}
