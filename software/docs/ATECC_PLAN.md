# ATECC508A secure element plan

How Soteria uses the ATECC508A (U4, I2C 0x60, shared with the EEPROM and
the OLED). Status: **phase 3 done**. The board's chip is provisioned and
locked with the slot map below, and the wallet firmware (0.5.0) keeps its
secrets in it. Slot rules and wallet flows were verified on the hardware.

## Threat model and decisions

Protect against **malware on the host** and **short physical access (1-2
days)**. Someone who keeps the board for a year or more will get in; by
then the owner should have moved the funds with the 12 words.

- **Tinkerer device, nothing permanently fused.** The SAMD21 stays
  unfused; the owner can always erase, reflash, change the PIN or PUK and
  regenerate every key, at their own risk.
- **One unavoidable exception: the ATECC itself must be locked once.**
  Without a locked config zone the chip has no real RNG, no GenKey and no
  slot rules; without a locked data zone it has no encrypted reads. The
  lock freezes the *rules* in the slot map below, never the *contents*:
  no slot is lockable or use-limited, every slot can be rewritten or
  regenerated, and every write path ends at the PUK
  (`test_plan_puk_reaches_every_slot`).
- **PUK:** 8 random hex characters (32 bits) generated at wallet creation
  and shown on the device like the 12 words. It authorises PIN changes,
  factory reset, firmware signing key / policy changes and re-pairing.
- **FIDO2 stays derived from the seed**, so it can be migrated with the 12
  words. The secret is sealed in the chip but readable without the PIN
  (as today, a security key must work without it).
- **No wipe after failed PINs.** On the 508A only the firmware can count
  attempts. Malicious firmware just skips the count, so a wipe adds risk
  for the owner and little security. The monotonic counter is still used
  to *show* failed attempts since the last unlock (a tamper hint).
- **No ATECC608 plans.**

## What the chip can and cannot do here

- **BTC/ETH keys stay on the MCU.** The 508A only knows NIST P-256, not
  secp256k1. It guards the seed: the root only leaves the chip,
  encrypted on the bus, to someone who knows the PIN. Signing stays on the
  SAMD21 with the root in RAM for as short as possible.
- **PIN guessing must go through this chip.** PIN and PUK are stretched
  inside the chip: repeated MAC with secret W, which can never be read.
  The 1-2 day budget per PIN length assumes about 1 s per guess (measured
  in phase 3: 0.9-1.0 s per PIN check).

  | PIN (hex digits) | combinations | share searched in 2 days at 1 guess/s |
  |---|---|---|
  | 5 (today's UI) | 1 M | 17 % |
  | 6 | 16.8 M | 1 % |
  | 8 | 4.3 G | 0.004 % |

  The recommendation is at least 6 digits. The PUK (8 hex) is stretched too.
- **Physical limit (evil maid).** With an unfused SAMD21 anyone with the
  SWD header can flash firmware that records the PIN the next time it is
  entered. The design protects a *stolen* device. It does not protect a
  *returned, tampered* one. Mitigations: a seal over the case/SWD header,
  and the optional, reversible SAMD21 security bit (phase 6).
- **Firmware gate (phase 5)** works against host malware, not against SWD:
  - a bootloader that only accepts images signed by the key in slot 10
    (checked with the chip's Verify);
  - unsigned "dev mode" can only be enabled in slot 11, i.e. with the PUK;
  - the 1200-baud "touch" reset to the bootloader must be removed (done:
    the wallet firmware cancels it in `sysTickHook()`; only a double tap
    of the reset button starts the bootloader)
    (`framework-arduino-samd-adafruit/cores/arduino/USB/CDC.cpp:123`).

## Slot map (`src/se/se_layout.h`)

ATECC508A slot sizes: 0-7 = 36 bytes, 8 = 416 bytes, 9-15 = 72 bytes.

| Slot | Role | SlotConfig | KeyConfig | Read | Write |
|---|---|---|---|---|---|
| 0 | identity key (P-256, attestation) | 0x2083 | 0x0013 | never (sign only) | GenKey (regenerate) |
| 1 | pairing secret P | 0x438F | 0x005C | never | encrypted, PUK |
| 2 | PIN verifier V | 0x438F | 0x005C | never | encrypted, PUK |
| 3 | PUK verifier M | 0x438F | 0x005C | never | encrypted, PUK |
| 4 | stretch secret W (MAC only) | 0x438F | 0x001C | never | encrypted, PUK |
| 5 | FIDO2 master secret (seed-derived) | 0x41C1 | 0x001C | encrypted, P | encrypted, P |
| 6 | spare P-256 key (sign, ECDH) | 0x2087 | 0x0013 | never | GenKey |
| 7 | spare P-256 key (sign, ECDH) | 0x2087 | 0x0013 | never | GenKey |
| 8 | spare storage, 416 B | 0x41C1 | 0x001C | encrypted, P | encrypted, P |
| 9 | wallet root (64 B, also MCU-encrypted) | 0x42C2 | 0x001C | encrypted, PIN | encrypted, PIN |
| 10 | firmware signing public key (data) | 0x4300 | 0x001C | clear | encrypted, PUK |
| 11 | firmware policy (dev mode, min version) | 0x4300 | 0x001C | clear | encrypted, PUK |
| 12 | counter value at last good PIN | 0x4200 | 0x001C | clear | encrypted, PIN |
| 13 | spare seed (hidden wallet) | 0x42C2 | 0x001C | encrypted, PIN | encrypted, PIN |
| 14 | spare public key (data) | 0x4300 | 0x001C | clear | encrypted, PUK |
| 15 | spare data | 0x41C1 | 0x001C | encrypted, P | encrypted, P |

Cross-checked with Coldcard's ATECC508A layout:
- Coldcard uses the same words for hidden keys (0x438F), seeds (0x43C3)
  and last-good counters (0x4300).
- As in Coldcard, never-readable secrets use ReadKey 0xF (ReadKey 0 would
  make them CheckMac/Copy sources), and the GenDig keys P, V and M require
  a random Nonce (ReqRandom).
- The firmware key slots 10/14 are plain data. The chip's Verify takes the
  public key in external mode.

Counter 0 counts PIN attempts. Counter 1 replaces the EEPROM FIDO2
signature counter (monotonic, no EEPROM wear). The rest of the config
zone stays as shipped: I2C address 0xC0, ChipMode (1.3 s watchdog), OTP
mode, counters, X509 0, no slot locks. GenKey on slots 0/6/7 is not gated
by the chip, only by the firmware (PUK prompt).

Not used: `ReqAuth` (AuthKey = P) on the PIN slot. With the optional
security bit it would have stopped a reflashed firmware from using a
phished PIN without re-pairing. Its semantics could not be verified before
the lock, and the lock now fixes the rules without it. Against an evil
maid, rely on a seal and the PIN counter display.

## Flows (phase 3+)

- **Factory state:** P, W random; V and M set from public values derived
  from the serial number, so a fresh or reset chip is never stuck.
- **Create wallet:** entropy = SHA-256(32 bytes from the chip's Random ||
  32 bytes of A0 noise from `RNGpin`). Before the config lock the chip's
  Random returns a fixed FF FF 00 00 pattern; the firmware rejects that
  pattern and refuses to create a wallet. The device
  shows the 12 words and then the PUK. It writes V, M, the root (slot 9),
  the FIDO2 secret (slot 5) and the counter (slot 12). The EEPROM only
  keeps public data (names, xpubs, public keys).
- **Unlock:** s = stretch(PIN), V = H("V" || s), K = H("K" || s). The
  device reads slot 9 encrypted with V and decrypts it with K. A wrong PIN
  gives garbage, which the fingerprint check rejects (as `hdUnlock` does
  today). The device then shows "N failed attempts since last unlock".
- **Change PIN:** old PIN + PUK. Slot 9 is re-encrypted.
- **Erase with PIN:** slots 9, 13 and 5 are overwritten with random. PIN
  and PUK stay.
- **Factory reset with PUK:** everything returns to factory state, with
  new P and W.
- **PIN and PUK both lost:** the funds are safe with the 12 words, but the
  PUK-guarded slots can never be reset. This is the only way to "waste" the
  chip, so write the PUK down with the words.
- **Pairing secret on the MCU:** the EEPROM (`SeRecord`, offset 0x0400),
  together with the other non-sensitive data (wallet name etc.).
  `pio run -t upload` runs bossac with `--erase`, which wipes the whole app
  flash, so a P kept in flash would not survive a reflash. With an unfused
  SAMD21 the EEPROM is no weaker than flash (both are readable with
  physical access; host malware reads neither). Wallet erase keeps P.

## Wallet on the chip (phase 3)

`src/se/se_wallet.cpp`, host-tested against a fake chip that enforces the
slot rules (`test/test_se_wallet`) and run on the real chip by `env:seprov_*`
(`WALLET TEST`).

- **Stretch:** x = SHA256(label | SN | digits), then 48 MAC rounds with W on
  the chip (16 per wake session, well inside the watchdog), then
  s = SHA256(P | x). P is mixed in because the last MAC crossed the bus in
  the clear.
  - PIN: V = SHA256("soteria-V" | s) and K = SHA256("soteria-K0"/"-K1" | s).
  - PUK: M = SHA256("soteria-M" | s).
- **PIN check by the chip:** the chip counts the attempt with counter 0
  (increment), then the firmware writes the counter value to slot 12,
  encrypted with V. Only the right V passes the chip's write MAC check.
  The previous value in slot 12 gives the number of wrong attempts since
  the last unlock.
- **Seed:** slot 9 holds (root XOR K), written and read encrypted with V.
  The root's fingerprint is checked against the EEPROM record.
- **Create:**
  - the factory PUK value (or the current PUK) authorises V;
  - then the device writes the counter, the seed and the FIDO2 secret
    (with P);
  - the new random PUK comes last, so an interrupted create can be
    repeated.
- **Wipe (PIN):** zeros in slots 9, 13 and 5; PIN and PUK stay.
- **Factory reset (PUK):** V back to factory, wallet zeroed, M back to
  factory, then a new random W. M changes before W, because the user's PUK
  depends on W.
- **Change PIN:** unseal with the old PIN, write the new V with the PUK,
  reseal.

Measured on the board (2026-10-29), `WALLET TEST`:
- all checks pass, and the chip is back in factory state afterwards;
- a PIN check takes about 0.9-1.0 s (one guess per second, as planned);
- creating a wallet takes about 2.1 s (PIN and PUK stretches plus writes).

## PIN and PUK entry (two buttons only)

YES and NO are the only inputs; the board has no analog input for a PIN.

- The device enters one hex digit at a time. **NO** steps the shown digit
  (0-F, wrapping); **YES** accepts it and moves to the next digit.
- Each digit starts at a random value (from the chip's RNG). Counting
  presses, or watching the button timing, then reveals nothing about the
  digit.
- The length is fixed: 6 digits for the PIN, 8 for the PUK. A fixed length
  means there is no "done" key to need.
- After the last digit the device asks for confirmation (YES), or offers
  to start over (NO). There is no cancel: a request that times out is
  rejected (as `askPin` does today).

## Phases

1. **Done:** read-only driver (`src/se/atecc.*`), planned slot map
   (`src/se/se_layout.h`), probe firmware (`env:setest_*`), host tests with
   a fake chip (`test/test_atecc`).
2. **Done:** provisioning firmware (`env:seprov_*`, see below).
3. **Done:** wallet on the chip (`src/se/se_wallet.*`, below). Also
   FIDO2: the secret is in slot 5 and the signature counter is counter 1.
   No migration: older wallets are not recognised (decision: latest
   format only).
4. Optional: FIDO2 attestation with the slot 0 key (now self-attestation).
5. Firmware gate: signed bootloader, slots 10/11. The 1200-baud reset is
   already removed: only a double tap of the reset button starts the
   bootloader.
6. Optional, reversible SAMD21 security bit; `device_attest` command.

## Provisioning (phase 2)

```
pio run -e seprov_feather_m0 -t upload && pio device monitor -e seprov_feather_m0
```

One command per line:
- `c` writes SlotConfig/KeyConfig (can be redone).
- `LOCK CONFIG` locks the config zone after checking it against the plan
  with a CRC.
- `d` writes the factory state (can be redone):
  - P and W from the chip RNG mixed with A0 noise; P goes to the EEPROM
    (offset 0x0400);
  - the PIN and PUK verifiers from the public values derived from the
    serial number;
  - zeros everywhere else.
- `LOCK DATA` locks the data zone, generates the keys in slots 0/6/7 and
  runs `v`.
- `v` verifies the rules. It can be rerun at any time and changes nothing
  permanently.

Notes from the run:
- Before the data lock the chip only accepts whole 32-byte block writes:
  - the 4-byte tails of 36/72-byte slots stay as shipped (they are never
    used);
  - the private key slots refuse clear writes (GenKey only).
- The data zone is locked without a CRC, like Coldcard. Every write was
  CRC-checked by the chip, and the verification proves the contents.

**Result on the board (2026-10-29), chip 0123E59156E00F25EE:**
- The config zone was locked with CRC 0x7F4F (= plan); the data zone is
  locked; identity and spare keys were generated.
- Verified on the chip:
  - encrypted read and write with P, the PIN key and the PUK key;
  - clear reads of secrets, wrong-key reads, wrong-key writes and clear
    writes are all refused;
  - a wrong PIN reads garbage;
  - MAC with W matches the host computation;
  - the PUK rewrites P, the PIN verifier and itself; the PIN cannot
    rewrite the PUK.
- The chip was left in factory state (public PIN/PUK verifiers), ready
  for the wallet firmware (phase 3).

## Running the probe (phase 1)

```
pio run -e setest_feather_m0 -t upload && pio device monitor -e setest_feather_m0
```

The probe never writes to or locks the chip.
- `i`: I2C scan, Info, config dump, slot map compared with the plan.
- `s`: 300 rounds of Info + config read alternating with OLED frames
  (shared-bus test).

Flash the wallet env again afterwards.

**Result on the board (2026-10-29):**
- ATECC508A (revision 00 00 50 00) at 0x60, genuine serial pattern.
- Config and data zones **unlocked**, Microchip factory config (OTP mode
  0x55). The factory SlotConfig of slot 0 is 0x2083, the same encoding as
  planned for the identity key.
- Stress test: 300 rounds of Info + config read alternating with OLED
  frames: 0 failures, 0 mismatches, 62 ms per round.
- Bus scan also finds 0x58, probably the EEPROM's identification page; it
  is not used. Please don't post the full config
dump publicly: it contains the chip's serial number.
