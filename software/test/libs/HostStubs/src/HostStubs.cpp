// Host stand-ins for the Arduino core, the I2C EEPROM, USB HID and the few
// wallet.cpp / display_fx.cpp functions the tested sources call.
#include <array>
#include <chrono>
#include <deque>
#include <thread>

#include "HostStubs.h"
#include <USB/PluggableUSB.h>
#include <Wire.h>
#include <wallet.h>

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

uint8_t TwoWire::endTransmission() {
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

// Same as src/wallet.cpp
bool loadFidoSecret(SecureStorage &eeprom, uint8_t secret[32]) {
    Key k;
    eeprom.getKey(FIDO_KEY_SLOT, k);
    if (k.network != U2F || k.id != FIDO_KEY_SLOT) return false;
    memcpy(secret, k.privateKey.data(), 32);
    return true;
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
