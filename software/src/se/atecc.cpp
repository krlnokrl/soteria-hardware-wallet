#include "atecc.h"
#include <Hash.h>

// Word address byte that starts every write to the chip
#define WA_RESET   0x00
#define WA_SLEEP   0x01
#define WA_IDLE    0x02
#define WA_COMMAND 0x03

#define OP_MAC    0x08
#define OP_READ   0x02
#define OP_WRITE  0x12
#define OP_GENDIG 0x15
#define OP_NONCE  0x16
#define OP_LOCK   0x17
#define OP_RANDOM 0x1B
#define OP_COUNTER 0x24
#define OP_INFO   0x30
#define OP_GENKEY 0x40

#define ZONE_CONFIG 0x00
#define ZONE_DATA   0x02
#define SIZE_32     0x80   // param1 flag: 32 bytes instead of 4

#define LOCK_CONFIG      0x00
#define LOCK_DATA_NO_CRC 0x81
#define GENKEY_PRIVATE   0x04
#define GENKEY_PUBLIC    0x00
#define MAC_MODE         0x40   // challenge from input, include SN[2:7]

#define POLL_SLACK_MS 5
#define WAKE_US 2000       // tWHI is 1.5 ms after the wake pulse
#define RETRIES 3
#define MACS_PER_SESSION 16   // 16 x 14 ms max, well inside the 1.3 s watchdog

static const uint8_t WAKE_TOKEN[4] = { 0x04, 0x11, 0x33, 0x43 };

// Max execution times in ms (datasheet; Nonce as measured by Coldcard).
static uint16_t execMs(uint8_t opcode) {
    switch (opcode) {
        case OP_READ:   return 1;
        case OP_INFO:   return 2;
        case OP_GENDIG: return 11;
        case OP_MAC:    return 14;
        case OP_COUNTER: return 20;
        case OP_RANDOM: return 23;
        case OP_WRITE:  return 26;
        case OP_NONCE:  return 30;
        case OP_LOCK:   return 32;
        case OP_GENKEY: return 115;
        default:        return 100;
    }
}

const char *ateccStatusName(uint8_t status) {
    switch (status) {
        case ATECC_SUCCESS:       return "ok";
        case ATECC_CHECKMAC_FAIL: return "checkmac/verify failed";
        case ATECC_PARSE_ERROR:   return "parse error";
        case ATECC_ECC_FAULT:     return "ecc fault";
        case ATECC_EXEC_ERROR:    return "execution error";
        case ATECC_AFTER_WAKE:    return "wake token";
        case ATECC_WATCHDOG:      return "watchdog about to expire";
        case ATECC_COMM_ERROR:    return "crc/communication error";
        case ATECC_NO_DEVICE:     return "no device";
        case ATECC_TIMEOUT:       return "timeout";
        case ATECC_BAD_RESPONSE:  return "bad response";
        default:                  return "unknown";
    }
}

// Transient failures worth a fresh wake and another try.
static bool retryable(uint8_t st) {
    return st == ATECC_COMM_ERROR || st == ATECC_WATCHDOG || st == ATECC_AFTER_WAKE ||
           st == ATECC_NO_DEVICE || st == ATECC_TIMEOUT || st == ATECC_BAD_RESPONSE;
}

// Run body (a sequence of commands) in one wake session, retrying the
// whole session on transient errors.
template <typename F>
static uint8_t inSession(Atecc &se, F body, int attempts = RETRIES) {
    uint8_t st = ATECC_NO_DEVICE;
    for (int attempt = 0; attempt < attempts; attempt++) {
        if (!se.wake()) { st = ATECC_NO_DEVICE; continue; }
        st = body();
        se.sleep();
        if (!retryable(st)) break;
    }
    return st;
}

static uint16_t dataAddr(uint8_t slot, uint8_t block, uint8_t word = 0) {
    return (uint16_t)(block << 8 | slot << 3 | word);
}

uint16_t Atecc::crc16(const uint8_t *data, size_t len) {
    uint16_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        for (uint8_t shift = 0x01; shift; shift <<= 1) {
            uint8_t dataBit = (data[i] & shift) ? 1 : 0;
            uint8_t crcBit = crc >> 15;
            crc <<= 1;
            if (dataBit != crcBit) crc ^= 0x8005;
        }
    }
    return crc;
}

static bool crcOk(const uint8_t *packet, uint8_t count) {
    uint16_t crc = Atecc::crc16(packet, count - 2);
    return packet[count - 2] == (uint8_t)crc && packet[count - 1] == (uint8_t)(crc >> 8);
}

/* ------------------------------------------------------------------ */
/* Transport                                                           */
/* ------------------------------------------------------------------ */

bool Atecc::wake() {
    for (int attempt = 0; attempt < 2; attempt++) {
        // At 100 kHz the 0x00 address byte holds SDA low for ~80 us, more
        // than the 60 us wake pulse; no device ACKs it.
        _wire.setClock(100000);
        _wire.beginTransmission(0x00);
        _wire.endTransmission();
        delayMicroseconds(WAKE_US);

        uint8_t token[4] = { 0 };
        if (_wire.requestFrom(_address, (size_t)4) == 4) {
            for (int i = 0; i < 4; i++) token[i] = (uint8_t)_wire.read();
            if (memcmp(token, WAKE_TOKEN, 4) == 0) return true;
        }
        // Already awake (pulse ignored) or a stale response: start over.
        sleep();
    }
    return false;
}

void Atecc::sleep() {
    _wire.beginTransmission(_address);
    _wire.write((uint8_t)WA_SLEEP);
    _wire.endTransmission();
}

void Atecc::idle() {
    _wire.beginTransmission(_address);
    _wire.write((uint8_t)WA_IDLE);
    _wire.endTransmission();
}

// Poll until the chip ACKs, then read count | data | crc. A 4-byte packet
// is a status; anything else must be exactly outLen data bytes.
uint8_t Atecc::receive(uint8_t *out, uint8_t outLen, uint16_t maxExecMs) {
    uint8_t buf[3 + 64];
    uint8_t want = outLen + 3 > 4 ? outLen + 3 : 4;
    if (want > sizeof(buf)) return ATECC_BAD_RESPONSE;

    // One poll per millisecond; counted rather than timed, so a coarse
    // millis() (host tests) cannot cut the wait short.
    uint8_t got = 0;
    for (uint16_t polls = 0; !got; polls++) {
        if (polls > maxExecMs + POLL_SLACK_MS) return ATECC_TIMEOUT;
        delay(1);
        got = _wire.requestFrom(_address, (size_t)want);
    }
    for (uint8_t i = 0; i < got; i++) buf[i] = (uint8_t)_wire.read();

    uint8_t count = buf[0];
    if (count < 4 || count > got || !crcOk(buf, count)) return ATECC_BAD_RESPONSE;
    if (count == 4 && outLen != 1) return buf[1] == ATECC_SUCCESS ? ATECC_BAD_RESPONSE : buf[1];
    if (count != outLen + 3) return ATECC_BAD_RESPONSE;
    memcpy(out, buf + 1, outLen);
    return ATECC_SUCCESS;
}

uint8_t Atecc::execute(uint8_t opcode, uint8_t param1, uint16_t param2,
                       const uint8_t *data, uint8_t len,
                       uint8_t *out, uint8_t outLen) {
    uint8_t packet[7 + 64];
    if (len > 64) return ATECC_PARSE_ERROR;
    uint8_t count = 7 + len;   // count, opcode, param1, param2 (2), data, crc (2)
    packet[0] = count;
    packet[1] = opcode;
    packet[2] = param1;
    packet[3] = (uint8_t)param2;
    packet[4] = (uint8_t)(param2 >> 8);
    if (len) memcpy(packet + 5, data, len);
    uint16_t crc = crc16(packet, count - 2);
    packet[count - 2] = (uint8_t)crc;
    packet[count - 1] = (uint8_t)(crc >> 8);

    _wire.beginTransmission(_address);
    _wire.write((uint8_t)WA_COMMAND);
    _wire.write(packet, count);
    if (_wire.endTransmission() != 0) return ATECC_NO_DEVICE;
    return receive(out, outLen, execMs(opcode));
}

// Commands that answer with a single status byte.
uint8_t Atecc::executeStatus(uint8_t opcode, uint8_t param1, uint16_t param2,
                             const uint8_t *data, uint8_t len) {
    uint8_t status = ATECC_BAD_RESPONSE;
    uint8_t st = execute(opcode, param1, param2, data, len, &status, 1);
    return st != ATECC_SUCCESS ? st : status;
}

/* ------------------------------------------------------------------ */
/* Read-only                                                           */
/* ------------------------------------------------------------------ */

uint8_t Atecc::info(uint8_t rev[4]) {
    return inSession(*this, [&]() {
        return execute(OP_INFO, 0x00, 0x0000, nullptr, 0, rev, 4);
    });
}

uint8_t Atecc::readConfig(uint8_t config[ATECC_CONFIG_SIZE]) {
    return inSession(*this, [&]() {
        // Config address = block << 3 | word; four 32-byte blocks
        uint8_t st = ATECC_SUCCESS;
        for (uint8_t block = 0; block < ATECC_CONFIG_SIZE / 32 && st == ATECC_SUCCESS; block++) {
            st = execute(OP_READ, ZONE_CONFIG | SIZE_32, (uint16_t)(block << 3),
                         nullptr, 0, config + 32 * block, 32);
        }
        return st;
    });
}

// Inside a session: SN[0:3] and SN[4:8] from config block 0.
uint8_t Atecc::loadSerial() {
    if (_haveSn) return ATECC_SUCCESS;
    uint8_t block[32];
    uint8_t st = execute(OP_READ, ZONE_CONFIG | SIZE_32, 0, nullptr, 0, block, 32);
    if (st != ATECC_SUCCESS) return st;
    memcpy(_sn, block, 4);
    memcpy(_sn + 4, block + 8, 5);
    _haveSn = true;
    return ATECC_SUCCESS;
}

uint8_t Atecc::serial(uint8_t sn[9]) {
    uint8_t st = inSession(*this, [&]() { return loadSerial(); });
    if (st == ATECC_SUCCESS) memcpy(sn, _sn, 9);
    return st;
}

/* ------------------------------------------------------------------ */
/* Randomness, Nonce and GenDig                                        */
/* ------------------------------------------------------------------ */

void Atecc::mixHostEntropy(const uint8_t *data, size_t len) {
    SHA256 h;
    h.write(_pool, sizeof(_pool));
    h.write(data, len);
    h.end(_pool);
}

void Atecc::nextNumIn(uint8_t numIn[20]) {
    uint32_t t = micros();
    SHA256 h;
    h.write(_pool, sizeof(_pool));
    h.write((const uint8_t *)&_nonces, sizeof(_nonces));
    h.write((const uint8_t *)&t, sizeof(t));
    h.end(_pool);
    _nonces++;
    memcpy(numIn, _pool, 20);
}

uint8_t Atecc::random(uint8_t out[32]) {
    return inSession(*this, [&]() {
        return execute(OP_RANDOM, 0x00, 0x0000, nullptr, 0, out, 32);
    });
}

// Inside a session: random Nonce, then GenDig over the key in keySlot.
// digest = the chip's new TempKey, computed here from the same inputs:
//   TempKey = SHA256(RandOut | NumIn | 16 00 00)
//   digest  = SHA256(key | 15 02 slot 00 | SN[8] SN[0:1] | 0*25 | TempKey)
uint8_t Atecc::authorize(uint8_t keySlot, const uint8_t key[32], uint8_t digest[32]) {
    uint8_t st = loadSerial();
    if (st != ATECC_SUCCESS) return st;

    uint8_t numIn[20], randOut[32], tempKey[32];
    nextNumIn(numIn);
    st = execute(OP_NONCE, 0x00, 0x0000, numIn, sizeof(numIn), randOut, 32);
    if (st != ATECC_SUCCESS) return st;
    static const uint8_t nonceTail[3] = { OP_NONCE, 0x00, 0x00 };
    SHA256 h;
    h.write(randOut, 32);
    h.write(numIn, sizeof(numIn));
    h.write(nonceTail, sizeof(nonceTail));
    h.end(tempKey);

    st = executeStatus(OP_GENDIG, ZONE_DATA, keySlot, nullptr, 0);
    if (st != ATECC_SUCCESS) return st;
    const uint8_t args[7] = { OP_GENDIG, ZONE_DATA, keySlot, 0x00, _sn[8], _sn[0], _sn[1] };
    static const uint8_t zeros[25] = { 0 };
    SHA256 d;
    d.write(key, 32);
    d.write(args, sizeof(args));
    d.write(zeros, sizeof(zeros));
    d.write(tempKey, 32);
    d.end(digest);
    return ATECC_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Data zone                                                           */
/* ------------------------------------------------------------------ */

uint8_t Atecc::read32(uint8_t slot, uint8_t block, uint8_t out[32]) {
    return inSession(*this, [&]() {
        return execute(OP_READ, ZONE_DATA | SIZE_32, dataAddr(slot, block), nullptr, 0, out, 32);
    });
}

uint8_t Atecc::readEncrypted(uint8_t slot, uint8_t block, uint8_t keySlot,
                             const uint8_t key[32], uint8_t out[32]) {
    uint8_t digest[32];
    uint8_t st = inSession(*this, [&]() {
        uint8_t s = authorize(keySlot, key, digest);
        if (s != ATECC_SUCCESS) return s;
        return execute(OP_READ, ZONE_DATA | SIZE_32, dataAddr(slot, block), nullptr, 0, out, 32);
    });
    if (st == ATECC_SUCCESS) {
        for (int i = 0; i < 32; i++) out[i] ^= digest[i];
    }
    memset(digest, 0, sizeof(digest));
    return st;
}

// Write data: (plaintext XOR digest) | MAC, where
//   MAC = SHA256(digest | 12 p1 addr(2) | SN[8] SN[0:1] | 0*25 | plaintext)
uint8_t Atecc::writeEncrypted(uint8_t slot, uint8_t block, uint8_t keySlot,
                              const uint8_t key[32], const uint8_t data[32]) {
    const uint8_t p1 = ZONE_DATA | SIZE_32;
    const uint16_t addr = dataAddr(slot, block);
    uint8_t st = inSession(*this, [&]() {
        uint8_t digest[32], body[64];
        uint8_t s = authorize(keySlot, key, digest);
        if (s != ATECC_SUCCESS) return s;
        for (int i = 0; i < 32; i++) body[i] = data[i] ^ digest[i];
        const uint8_t args[7] = { OP_WRITE, p1, (uint8_t)addr, (uint8_t)(addr >> 8),
                                  _sn[8], _sn[0], _sn[1] };
        static const uint8_t zeros[25] = { 0 };
        SHA256 h;
        h.write(digest, 32);
        h.write(args, sizeof(args));
        h.write(zeros, sizeof(zeros));
        h.write(data, 32);
        h.end(body + 32);
        s = executeStatus(OP_WRITE, p1, addr, body, sizeof(body));
        memset(digest, 0, sizeof(digest));
        memset(body, 0, sizeof(body));
        return s;
    });
    return st;
}

uint8_t Atecc::mac(uint8_t slot, const uint8_t challenge[32], uint8_t out[32]) {
    return inSession(*this, [&]() {
        return execute(OP_MAC, MAC_MODE, slot, challenge, 32, out, 32);
    });
}

uint8_t Atecc::macChain(uint8_t slot, uint8_t io[32], uint16_t rounds) {
    while (rounds) {
        uint16_t n = rounds < MACS_PER_SESSION ? rounds : MACS_PER_SESSION;
        uint8_t st = inSession(*this, [&]() {
            uint8_t buf[32];
            memcpy(buf, io, 32);
            for (uint16_t i = 0; i < n; i++) {
                uint8_t s = execute(OP_MAC, MAC_MODE, slot, buf, 32, buf, 32);
                if (s != ATECC_SUCCESS) return s;
            }
            memcpy(io, buf, 32);   // only a complete chunk counts (retry-safe)
            return (uint8_t)ATECC_SUCCESS;
        });
        if (st != ATECC_SUCCESS) return st;
        rounds -= n;
    }
    return ATECC_SUCCESS;
}

uint8_t Atecc::counter(uint8_t id, bool increment, uint32_t &value) {
    uint8_t out[4];
    // Increment is not idempotent: no session retry once it was sent.
    uint8_t st = inSession(*this, [&]() {
        return execute(OP_COUNTER, increment ? 0x01 : 0x00, id, nullptr, 0, out, 4);
    }, increment ? 1 : RETRIES);
    if (st == ATECC_SUCCESS) value = (uint32_t)out[0] | out[1] << 8 | out[2] << 16 | (uint32_t)out[3] << 24;
    return st;
}

uint8_t Atecc::genKey(uint8_t slot, uint8_t pub[64]) {
    return inSession(*this, [&]() {
        return execute(OP_GENKEY, GENKEY_PRIVATE, slot, nullptr, 0, pub, 64);
    });
}

uint8_t Atecc::publicKey(uint8_t slot, uint8_t pub[64]) {
    return inSession(*this, [&]() {
        return execute(OP_GENKEY, GENKEY_PUBLIC, slot, nullptr, 0, pub, 64);
    });
}

/* ------------------------------------------------------------------ */
/* Provisioning                                                        */
/* ------------------------------------------------------------------ */

uint8_t Atecc::writeSlotConfig(const uint8_t config[ATECC_CONFIG_SIZE]) {
    // Config word address = byte offset / 4: SlotConfig = words 5..12
    // (bytes 20..51), KeyConfig = words 24..31 (bytes 96..127).
    for (uint8_t word = 5; word < 32; word++) {
        if (word == 13) word = 24;
        uint8_t st = inSession(*this, [&]() {
            return executeStatus(OP_WRITE, ZONE_CONFIG, word, config + 4 * word, 4);
        });
        if (st != ATECC_SUCCESS) return st;
    }
    return ATECC_SUCCESS;
}

// Whole 32-byte blocks only (as Coldcard does; the chip refuses the 4-byte
// tail writes): len is rounded down, the tail of 36/72-byte slots stays.
uint8_t Atecc::writeSlotClear(uint8_t slot, const uint8_t *data, uint16_t len) {
    for (uint8_t block = 0; block < len / 32; block++) {
        uint8_t st = inSession(*this, [&]() {
            return executeStatus(OP_WRITE, ZONE_DATA | SIZE_32, dataAddr(slot, block),
                                 data + 32 * block, 32);
        });
        if (st != ATECC_SUCCESS) return st;
    }
    return ATECC_SUCCESS;
}

// One attempt only: a lock may have happened even if its answer got lost,
// so the caller re-reads the config zone instead of retrying.
uint8_t Atecc::lockConfig(uint16_t crc) {
    return inSession(*this, [&]() {
        return executeStatus(OP_LOCK, LOCK_CONFIG, crc, nullptr, 0);
    }, 1);
}

uint8_t Atecc::lockData() {
    return inSession(*this, [&]() {
        return executeStatus(OP_LOCK, LOCK_DATA_NO_CRC, 0x0000, nullptr, 0);
    }, 1);
}
