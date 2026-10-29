#pragma once
// Host stand-in for the I2C bus with a 24C64-style EEPROM at 0x50
// (32-byte write pages that wrap, NAK while an internal write runs) and
// a fake ATECC508A at 0x60 (HostStubs.h).
#include <Arduino.h>
class TwoWire {
public:
    void begin() {}
    void setClock(uint32_t) {}
    void beginTransmission(uint8_t addr);
    size_t write(uint8_t b);
    size_t write(const uint8_t *d, size_t n);
    uint8_t endTransmission();
    uint8_t requestFrom(uint8_t addr, size_t n);
    int available();
    int read();
};
extern TwoWire Wire;
