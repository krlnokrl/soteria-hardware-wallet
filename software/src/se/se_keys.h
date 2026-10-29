#ifndef SE_KEYS_H
#define SE_KEYS_H

// Values the firmware derives for the secure element (docs/ATECC_PLAN.md).
#include <stdint.h>

// Public "factory" contents of the PIN and PUK verifier slots, bound to
// the chip's serial number. A fresh or factory-reset chip holds these, so
// it can always be set up again; they protect nothing.
void seFactoryPin(const uint8_t sn[9], uint8_t out[32]);
void seFactoryPuk(const uint8_t sn[9], uint8_t out[32]);

// What the chip answers to Atecc::mac(slot, challenge) when the slot holds
// key: SHA256(key | challenge | 08 40 slot 00 | 0*11 | SN[8] | SN[4:7] |
// SN[0:1] | SN[2:3]).
void seExpectedMac(const uint8_t key[32], const uint8_t challenge[32], uint8_t slot,
                   const uint8_t sn[9], uint8_t out[32]);

#endif // SE_KEYS_H
