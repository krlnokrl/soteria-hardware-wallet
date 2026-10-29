// Host stand-ins for the Arduino core, the I2C EEPROM, USB HID and the few
// wallet.cpp / display_fx.cpp functions the tested sources call.
#include <array>
#include <chrono>
#include <deque>
#include <thread>
#include <vector>

#include "HostStubs.h"
#include <USB/PluggableUSB.h>
#include <Wire.h>
#include <wallet.h>
#include <Hash.h>
#include "se/se_layout.h"
#include "se/se_keys.h"

// FIDO2 secret and counter of the wallet (stand-ins below)
static uint8_t s_fidoSecret[32];
static bool s_fidoReady;
static uint32_t s_fidoCount;

/* ---------------- Arduino ---------------- */

static const auto s_start = std::chrono::steady_clock::now();
static int s_pressPin = -1;   // button that becomes pressed...
static int s_pressAfter = 0;  // ...after this many reads of it...
static int s_pressReads = 0;  // ...and stays pressed for this many

uint32_t millis() {
    return (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - s_start).count();
}
uint32_t micros() { return millis() * 1000; }
void delay(uint32_t ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }
void delayMicroseconds(uint32_t) {}
int analogRead(int) { return 0; }

int digitalRead(int pin) {
    if (pin != s_pressPin) return LOW;
    if (s_pressAfter > 0) { s_pressAfter--; return LOW; }
    if (s_pressReads > 0) { s_pressReads--; return HIGH; }
    s_pressPin = -1;
    return LOW;
}

void hostPress(int pin, int after, int reads) {
    s_pressPin = pin;
    s_pressAfter = after;
    s_pressReads = reads;
}

/* ---------------- I2C EEPROM (24C64) ---------------- */

static uint8_t s_mem[8192];
static uint16_t s_ptr;
static int s_busy;                       // transactions NAKed until the write cycle ends
static uint8_t s_txAddr;
static std::deque<uint8_t> s_tx, s_rx;
TwoWire Wire;

void TwoWire::beginTransmission(uint8_t a) { s_txAddr = a; s_tx.clear(); }
size_t TwoWire::write(uint8_t b) { s_tx.push_back(b); return 1; }
size_t TwoWire::write(const uint8_t *d, size_t n) { for (size_t i = 0; i < n; i++) s_tx.push_back(d[i]); return n; }

/* ---------------- ATECC508A secure element at 0x60 ---------------- */
// The chip as the firmware uses it: wake token, sleep/idle (clear TempKey),
// Info, Read/Write of config and data zones, Random, Nonce, GenDig, MAC,
// Counter. Data slots follow their SlotConfig once the data zone is
// locked: secrets only encrypted and only with the right key (the TempKey
// of a GenDig over ReadKey/WriteKey), encrypted writes need a valid MAC.
// CRC checks both ways, NAK while busy.

static bool s_seAwake, s_sePresent;
static int s_seBusy, s_seBusyPolls, s_seCorrupt;
static uint8_t s_seCfg[128];
static uint8_t s_seData[16][416];
static uint32_t s_seCounter[2], s_seRng;
static uint8_t s_seTempKey[32];
static bool s_seTempValid;
static int s_seGenDigSlot;               // slot the TempKey was digested with, -1 none
static std::vector<uint8_t> s_seResp, s_seOps;

static uint16_t seCrc(const uint8_t *d, size_t n) {
    uint16_t crc = 0;
    for (size_t i = 0; i < n; i++)
        for (int b = 0; b < 8; b++) {
            bool flip = (((d[i] >> b) & 1) != (crc >> 15));
            crc = (uint16_t)(crc << 1);
            if (flip) crc ^= 0x8005;
        }
    return crc;
}

// count | data | crc (LE)
static void seRespond(const uint8_t *data, size_t n) {
    s_seResp.assign(1, (uint8_t)(n + 3));
    s_seResp.insert(s_seResp.end(), data, data + n);
    uint16_t crc = seCrc(s_seResp.data(), s_seResp.size());
    s_seResp.push_back((uint8_t)crc);
    s_seResp.push_back((uint8_t)(crc >> 8));
}

static void seStatus(uint8_t st) { seRespond(&st, 1); }

static bool seLockedCfg()  { return s_seCfg[87] != 0x55; }
static bool seLockedData() { return s_seCfg[86] != 0x55; }
static uint16_t seSlotCfg(int s) { return (uint16_t)(s_seCfg[20 + 2 * s] | s_seCfg[21 + 2 * s] << 8); }
static uint16_t seKeyCfg(int s)  { return (uint16_t)(s_seCfg[96 + 2 * s] | s_seCfg[97 + 2 * s] << 8); }
static const uint8_t *seSn(int i) {   // &SN[i]
    static uint8_t sn[9];
    memcpy(sn, s_seCfg, 4);
    memcpy(sn + 4, s_seCfg + 8, 5);
    return sn + i;
}

static void seRandom(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        s_seRng ^= s_seRng << 13; s_seRng ^= s_seRng >> 17; s_seRng ^= s_seRng << 5;
        out[i] = (uint8_t)s_seRng;
    }
}

static void seForgetTempKey() { s_seTempValid = false; s_seGenDigSlot = -1; }

static void seDataCommand(uint8_t op, uint8_t p1, uint16_t p2, const uint8_t *in, size_t len) {
    int slot = (p2 >> 3) & 0x0F, block = p2 >> 8;
    uint16_t sc = seSlotCfg(slot);
    bool secret = sc & 0x80, encRead = sc & 0x40;
    int readKey = sc & 0x0F, writeKey = (sc >> 8) & 0x0F, writeCfg = sc >> 12;
    uint8_t *mem = s_seData[slot] + 32 * block;
    bool privKey = seKeyCfg(slot) & 0x01;
    if (!(p1 & 0x80)) { seStatus(0x0F); return; }             // only 32-byte access modelled
    if (op == 0x02) {                                         // Read
        if (!seLockedData() || (secret && !encRead) || privKey) { seStatus(0x0F); return; }
        uint8_t out[32];
        memcpy(out, mem, 32);
        if (secret) {
            if (!s_seTempValid || s_seGenDigSlot != readKey) { seStatus(0x0F); return; }
            for (int i = 0; i < 32; i++) out[i] ^= s_seTempKey[i];
            seForgetTempKey();
        }
        seRespond(out, 32);
        return;
    }
    if (!seLockedData()) {                                    // clear writes before the lock
        if (privKey || len != 32) { seStatus(0x0F); return; }
        memcpy(mem, in, 32);
        seStatus(0x00);
        return;
    }
    if (writeCfg != 0x4 || len != 64 || !s_seTempValid || s_seGenDigSlot != writeKey) {
        seForgetTempKey();
        seStatus(0x0F);
        return;
    }
    uint8_t plain[32], mac[32];
    for (int i = 0; i < 32; i++) plain[i] = in[i] ^ s_seTempKey[i];
    const uint8_t args[7] = { 0x12, p1, (uint8_t)p2, (uint8_t)(p2 >> 8), *seSn(8), *seSn(0), *seSn(1) };
    const uint8_t zeros[25] = { 0 };
    SHA256 h;
    h.write(s_seTempKey, 32); h.write(args, 7); h.write(zeros, 25); h.write(plain, 32);
    h.end(mac);
    seForgetTempKey();
    if (memcmp(mac, in + 32, 32) != 0) { seStatus(0x01); return; }
    memcpy(mem, plain, 32);
    seStatus(0x00);
}

static void seCommand() {
    std::vector<uint8_t> p(s_tx.begin() + 1, s_tx.end());   // after word address 0x03
    s_seBusy = s_seBusyPolls;
    if (p.size() < 7 || p[0] != p.size() || seCrc(p.data(), p.size() - 2) != (p[p.size() - 2] | p[p.size() - 1] << 8)) {
        seStatus(0xFF);
        return;
    }
    uint8_t op = p[1], p1 = p[2];
    uint16_t p2 = (uint16_t)(p[3] | p[4] << 8);
    const uint8_t *in = p.data() + 5;
    size_t len = p.size() - 7;
    s_seOps.push_back(op);
    if (op == 0x30 && p1 == 0) {                              // Info
        static const uint8_t rev[4] = { 0x00, 0x00, 0x50, 0x00 };
        seRespond(rev, 4);
    } else if ((op == 0x02 || op == 0x12) && (p1 & 0x03) == 0x02) {
        seDataCommand(op, p1, p2, in, len);
    } else if (op == 0x02) {                                  // Read config
        if ((p1 & 0x03) != 0) { seStatus(0x0F); return; }    // OTP not modelled
        size_t n = (p1 & 0x80) ? 32 : 4;
        size_t off = ((p2 >> 3) & 0x1F) * 32 + ((p1 & 0x80) ? 0 : (p2 & 7) * 4);
        if (off + n > sizeof(s_seCfg)) { seStatus(0x03); return; }
        seRespond(s_seCfg + off, n);
    } else if (op == 0x1B) {                                  // Random
        uint8_t r[32];
        if (!seLockedCfg()) for (int i = 0; i < 32; i++) r[i] = (i & 3) < 2 ? 0xFF : 0x00;
        else seRandom(r, 32);
        seRespond(r, 32);
    } else if (op == 0x16 && p1 == 0 && len == 20) {          // Nonce (random)
        uint8_t randOut[32];
        seRandom(randOut, 32);
        const uint8_t tail[3] = { 0x16, 0x00, 0x00 };
        SHA256 h;
        h.write(randOut, 32); h.write(in, 20); h.write(tail, 3);
        h.end(s_seTempKey);
        s_seTempValid = true;
        s_seGenDigSlot = -1;
        seRespond(randOut, 32);
    } else if (op == 0x15 && p1 == 0x02) {                    // GenDig over a data slot
        int k = p2 & 0x0F;
        if (!s_seTempValid || !seLockedData()) { seStatus(0x0F); return; }
        const uint8_t args[7] = { 0x15, 0x02, (uint8_t)k, 0x00, *seSn(8), *seSn(0), *seSn(1) };
        const uint8_t zeros[25] = { 0 };
        SHA256 h;
        h.write(s_seData[k], 32); h.write(args, 7); h.write(zeros, 25); h.write(s_seTempKey, 32);
        h.end(s_seTempKey);
        s_seGenDigSlot = k;
        seStatus(0x00);
    } else if (op == 0x08 && p1 == 0x40 && len == 32) {       // MAC, challenge mode
        int k = p2 & 0x0F;
        if (seSlotCfg(k) & 0x10) { seStatus(0x0F); return; }  // NoMac
        const uint8_t args[4] = { 0x08, 0x40, (uint8_t)k, 0x00 };
        const uint8_t zeros[11] = { 0 };
        uint8_t out[32];
        SHA256 h;
        h.write(s_seData[k], 32); h.write(in, 32); h.write(args, 4); h.write(zeros, 11);
        h.write(seSn(8), 1); h.write(seSn(4), 4); h.write(seSn(0), 2); h.write(seSn(2), 2);
        h.end(out);
        seRespond(out, 32);
    } else if (op == 0x24 && p2 < 2) {                        // Counter
        if (p1 == 0x01) s_seCounter[p2]++;
        uint8_t v[4];
        for (int i = 0; i < 4; i++) v[i] = (uint8_t)(s_seCounter[p2] >> (8 * i));
        seRespond(v, 4);
    } else {
        seStatus(0x03);
    }
}

static uint8_t seEndTransmission() {
    if (!s_sePresent || !s_seAwake || s_seBusy > 0) return 2;
    if (s_tx.empty()) return 0;
    switch (s_tx[0]) {
        case 0x01: case 0x02:                                 // sleep / idle
            s_seAwake = false;
            s_seResp.clear();
            seForgetTempKey();
            break;
        case 0x03: seCommand(); break;
        default: s_seResp.clear(); break;
    }
    return 0;
}

static uint8_t seRequestFrom(size_t n) {
    if (!s_sePresent || !s_seAwake) return 0;
    if (s_seBusy > 0) { s_seBusy--; return 0; }
    if (s_seCorrupt > 0 && !s_seResp.empty()) { s_seCorrupt--; s_seResp.back() ^= 0x01; }
    for (size_t i = 0; i < n; i++) s_rx.push_back(i < s_seResp.size() ? s_seResp[i] : 0xFF);
    s_seResp.clear();
    return (uint8_t)n;
}

void hostAteccReset() {
    static const uint8_t factory[128] = {
        0x01, 0x23, 0x6B, 0x2A, 0x00, 0x00, 0x50, 0x00, 0x91, 0x3F, 0x0C, 0x55, 0xEE, 0x01, 0x71, 0x00,
        0xC0, 0x00, 0x55, 0x00, 0x8F, 0x20, 0xC4, 0x44, 0x87, 0x20, 0x87, 0x20, 0x8F, 0x0F, 0xC4, 0x36,
        0x9F, 0x0F, 0x82, 0x20, 0x0F, 0x0F, 0xC4, 0x44, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
        0x0F, 0x0F, 0x0F, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x55, 0x55, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x33, 0x00, 0x1C, 0x00, 0x13, 0x00, 0x13, 0x00, 0x7C, 0x00, 0x1C, 0x00, 0x3C, 0x00, 0x33, 0x00,
        0x3C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x30, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x30, 0x00,
    };
    memcpy(s_seCfg, factory, sizeof(s_seCfg));
    s_seAwake = false;
    s_sePresent = true;
    s_seBusy = 0;
    s_seBusyPolls = 2;
    s_seCorrupt = 0;
    s_seResp.clear();
    s_seOps.clear();
    memset(s_seData, 0, sizeof(s_seData));
    s_seCounter[0] = s_seCounter[1] = 0;
    s_seRng = 0x2545F491;
    seForgetTempKey();
}

void hostAteccProvision(const uint8_t pairing[32], const uint8_t stretch[32]) {
    uint8_t sn[9];
    memcpy(sn, s_seCfg, 4);
    memcpy(sn + 4, s_seCfg + 8, 5);
    uint8_t cfg[128];
    seBuildConfig(s_seCfg, cfg);
    memcpy(s_seCfg, cfg, sizeof(cfg));
    s_seCfg[86] = s_seCfg[87] = 0x00;                         // both zones locked
    memset(s_seData, 0, sizeof(s_seData));
    memcpy(s_seData[SE_SLOT_PAIRING], pairing, 32);
    seFactoryPin(sn, s_seData[SE_SLOT_PIN]);
    seFactoryPuk(sn, s_seData[SE_SLOT_PUK]);
    memcpy(s_seData[SE_SLOT_STRETCH], stretch, 32);
}

void hostAteccSetPresent(bool present) { s_sePresent = present; }
void hostAteccSetBusyPolls(int polls) { s_seBusyPolls = polls; }
void hostAteccCorrupt(int responses) { s_seCorrupt = responses; }
uint8_t *hostAteccConfig() { return s_seCfg; }
const std::vector<uint8_t> &hostAteccOpcodes() { return s_seOps; }

uint8_t TwoWire::endTransmission() {
    if (s_txAddr == 0x00) {   // general call: the wake pulse
        if (s_sePresent && !s_seAwake) { s_seAwake = true; seStatus(0x11); }
        return 2;             // nobody ACKs it
    }
    if (s_txAddr == 0x60) return seEndTransmission();
    if (s_txAddr != 0x50) return 2;
    if (s_busy > 0) { s_busy--; return 2; }   // address NAK while writing
    if (s_tx.size() >= 2) {
        s_ptr = (uint16_t)(((s_tx[0] << 8) | s_tx[1]) & 0x1FFF);
        if (s_tx.size() > 2) {
            uint16_t page = s_ptr & ~31, off = s_ptr & 31;
            for (size_t i = 2; i < s_tx.size(); i++) {   // wraps inside the page
                s_mem[page + off] = s_tx[i];
                off = (off + 1) & 31;
            }
            s_busy = 3;
        }
    }
    return 0;
}

uint8_t TwoWire::requestFrom(uint8_t a, size_t n) {
    s_rx.clear();
    if (a == 0x60) return seRequestFrom(n);
    if (a != 0x50 || s_busy > 0) { if (s_busy) s_busy--; return 0; }
    for (size_t i = 0; i < n; i++) { s_rx.push_back(s_mem[s_ptr]); s_ptr = (s_ptr + 1) & 0x1FFF; }
    return (uint8_t)n;
}
int TwoWire::available() { return (int)s_rx.size(); }
int TwoWire::read() { int c = s_rx.front(); s_rx.pop_front(); return c; }

/* ---------------- USB HID ---------------- */

static std::deque<std::array<uint8_t, 64>> s_out, s_in;   // host->device, device->host
USBDeviceClass USBDevice;
USBDevice_SAMD21G18x usbd;
PluggableUSB_ &PluggableUSB() { static PluggableUSB_ p; return p; }

uint32_t USBDeviceClass::send(uint32_t, const void *data, uint32_t len) {
    std::array<uint8_t, 64> p{};
    memcpy(p.data(), data, len < 64 ? len : 64);
    s_in.push_back(p);
    return len;
}
uint32_t USBDeviceClass::available(uint32_t) { return s_out.empty() ? 0 : 64; }
uint32_t USBDeviceClass::recv(uint32_t, void *data, uint32_t len) {
    if (s_out.empty()) return 0;
    uint32_t n = len < 64 ? len : 64;
    memcpy(data, s_out.front().data(), n);
    s_out.pop_front();
    return n;
}

void hostUsbOut(const uint8_t pkt[64]) {
    std::array<uint8_t, 64> p;
    memcpy(p.data(), pkt, 64);
    s_out.push_back(p);
}

bool hostUsbIn(uint8_t pkt[64]) {
    if (s_in.empty()) return false;
    memcpy(pkt, s_in.front().data(), 64);
    s_in.pop_front();
    return true;
}

void hostReset() {
    memset(s_mem, 0xFF, sizeof(s_mem));
    s_busy = 0;
    s_out.clear();
    s_in.clear();
    s_pressPin = -1;
    hostAteccReset();
    hostSetFidoSecret(nullptr);
    s_fidoCount = 0;
}

/* ---------------- wallet.cpp / display_fx.cpp stand-ins ---------------- */

// Deterministic "noise": tests must be reproducible.
int RNGpin(uint8_t *dest, unsigned size) {
    static uint32_t x = 0x12345678;
    while (size--) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        *dest++ = (uint8_t)x;
    }
    return 1;
}

// The secure element's FIDO2 secret and counter (src/wallet.cpp; the
// SeWallet behind them is tested in test_se_wallet).

void hostSetFidoSecret(const uint8_t *secret) {
    s_fidoReady = secret != nullptr;
    if (secret) memcpy(s_fidoSecret, secret, 32);
}

bool loadFidoSecret(uint8_t secret[32]) {
    if (!s_fidoReady) return false;
    memcpy(secret, s_fidoSecret, 32);
    return true;
}

bool fidoCounter(uint32_t &value, bool increment) {
    if (increment) s_fidoCount++;
    value = s_fidoCount;
    return true;
}

void walletRandom(uint8_t *out, size_t len) {
    RNGpin(out, (unsigned)len);
}

void displayYesNo(Adafruit_SSD1306 &) {}

// trezor-crypto's randomness hooks (rand.c defines them weak, which MinGW
// does not resolve from a static library). Only blinding uses them here;
// signatures are deterministic (RFC 6979).
extern "C" uint32_t random32(void) {
    uint32_t v;
    RNGpin((uint8_t *)&v, sizeof(v));
    return v;
}

extern "C" void random_buffer(uint8_t *buf, size_t len) {
    RNGpin(buf, (unsigned)len);
}
