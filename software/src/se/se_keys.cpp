#include "se_keys.h"
#include <string.h>
#include <Hash.h>

static void factoryValue(const char *label, const uint8_t sn[9], uint8_t out[32]) {
    SHA256 h;
    h.write((const uint8_t *)label, strlen(label));
    h.write(sn, 9);
    h.end(out);
}

void seFactoryPin(const uint8_t sn[9], uint8_t out[32]) { factoryValue("soteria-factory-pin", sn, out); }
void seFactoryPuk(const uint8_t sn[9], uint8_t out[32]) { factoryValue("soteria-factory-puk", sn, out); }

void seExpectedMac(const uint8_t key[32], const uint8_t challenge[32], uint8_t slot,
                   const uint8_t sn[9], uint8_t out[32]) {
    const uint8_t args[4] = { 0x08, 0x40, slot, 0x00 };
    static const uint8_t zeros[11] = { 0 };
    SHA256 h;
    h.write(key, 32);
    h.write(challenge, 32);
    h.write(args, sizeof(args));
    h.write(zeros, sizeof(zeros));   // OTP not included (mode bits 4, 5 clear)
    h.write(sn + 8, 1);
    h.write(sn + 4, 4);
    h.write(sn, 2);
    h.write(sn + 2, 2);
    h.end(out);
}
