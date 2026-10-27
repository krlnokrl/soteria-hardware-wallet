#pragma once
// Host stand-in for ricmoo/QRCode (only the type is needed).
#include <stdint.h>
typedef struct QRCode {
    uint8_t version, ecc, mode, mask, size;
    uint8_t *modules;
} QRCode;
