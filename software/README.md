# Soteria Wallet

Soteria Wallet is a small hardware-wallet-style project built for the Adafruit Feather M0 / MZero Pro USB class of boards. The goal is to create a compact, self-contained device that can generate a seed, derive cryptocurrency keys, display wallet addresses as QR codes, and sign simple requests over USB without exposing the private key on a general-purpose computer.

This project is intentionally experimental and educational: it combines a low-power Arduino/PlatformIO firmware with an OLED display, a button interface, and a wallet generation flow modeled after Bitcoin and Ethereum key derivation.

## What the project is trying to achieve

The firmware aims to provide a minimal wallet experience in a secure-ish hardware form factor:

- Generate a wallet seed and derive keys for Bitcoin, Ethereum, FIDO U2F, and Bitcoin testnet
- Keep the wallet secret in an ATECC508A secure element, released only for the right PIN
- Store only public, non-sensitive data (xpubs, public keys, name) in the EEPROM
- Present wallet addresses and QR codes on an SSD1306 display
- Accept USB-based commands to read addresses or sign payloads
- Offer a simple UI for first-time setup, verification, and wipe/reset flows

In other words, it is trying to behave like a lightweight hardware wallet prototype that runs on embedded hardware and keeps the wallet logic close to the user instead of in a desktop app.

## Main features

- BIP39 seed generation and mnemonic handling
- Hierarchical deterministic key derivation for:
  - Bitcoin mainnet
  - Bitcoin testnet
  - Ethereum
  - FIDO U2F
- QR code display for addresses
- OLED-based user prompts and menu flow
- JSON-lines host protocol over USB serial (always on; see `web-client/README.md`)
- ATECC508A secure element: sealed seed, in-chip PIN check and stretching, PUK, monotonic counters, hardware RNG
- EEPROM for public wallet data and the secure element pairing record

## Code structure

The project is organized around a small embedded firmware layout:

### src/main.cpp
This is the main application loop. It is responsible for:

- setting up the display and GPIO
- checking whether a wallet already exists
- prompting the user to generate one if none is present
- showing wallet addresses in a rotating display loop
- servicing the FIDO2 (USB HID) and host protocol (USB serial) interfaces from every UI loop

This is the entry point that coordinates the visible device behavior.

### src/wallet.h
This header declares the wallet-related APIs. It defines the public functions used throughout the firmware, including:

- wallet generation
- string parsing helpers
- transaction signing helpers
- device erase logic
- yes/no and pin-entry UX helpers

This file is the contract between the main firmware and the wallet logic implementation.

### src/wallet.cpp
This is the core wallet logic. It contains the device’s security and key management behavior, including:

- randomness: secure element RNG mixed with A0 noise
- PIN/PUK entry with the two buttons
- BIP39 mnemonic generation
- HD key derivation for BTC, BTCT, ETH, and U2F paths
- sealing the root in the secure element, unlocking it with the PIN
- erase (PIN) / factory reset (PUK), PIN change
- message signing flows for Bitcoin and Ethereum

This is the most important implementation file in the project.

### src/display/display_fx.h and src/display/display_fx.cpp
These files handle all of the OLED drawing helpers used by the menu and wallet UI, including:

- loading the Soteria logo
- drawing the sandglass progress animation
- drawing progress bars
- showing QR codes
- drawing the Yes/No prompt labels

They keep the display code isolated from the crypto logic so the device UI remains easier to manage.

### src/protocol.h and src/protocol.cpp
The host protocol: reads JSON request lines from USB serial, dispatches commands (info, addresses, signing, rename, erase), emits `confirm_on_device` events and writes JSON replies.

### src/crypto/ethtx.h and src/crypto/ethtx.cpp
Ethereum transaction support: RLP parsing of unsigned EIP-155 / EIP-1559 transactions for on-device display, ERC-20 call recognition, the EVM chain name/symbol table, signed re-encoding, fee and unit formatting, EIP-191 message hashing.

### src/crypto/btchd.h and src/crypto/btchd.cpp
Bitcoin HD wallet: BIP84 (native SegWit) accounts and addresses, output descriptors, bech32/bech32m address encoding, strict structural validation of host transactions and PSBTs, PSBT review (fee, change detection) and signing.

### src/buttons.h and src/buttons.cpp
Debounced, edge-triggered handling of the YES/NO buttons. A press only counts if it started after the current prompt appeared, so a button held from the previous screen never answers the next one.

### src/se/, src/setest/ and src/seprov/
ATECC508A secure element:
- an I2C driver (encrypted read/write, MAC, GenKey) and the slot map (`se_layout.h`);
- a read-only probe firmware (`env:setest_*`);
- the provisioning firmware that locks the chip with that map and verifies its rules (`env:seprov_*`).

`se_wallet.h` holds the wallet logic on the chip (create, unlock, PIN change, wipe, factory reset, FIDO2 secret and counter), independent of the display, so it is host-tested. The pairing secret lives in the EEPROM. See [docs/ATECC_PLAN.md](docs/ATECC_PLAN.md).

### lib/bip39/
This is the bundled mnemonic wordlist and BIP39 implementation used by the wallet. It provides the word list and helper code required to generate and verify mnemonic phrases.

### platformio.ini
This file configures the PlatformIO environment for the target boards.
The project currently targets embedded SAM boards and includes the required libraries for:

- OLED display
- USB access
- QR code generation
- Bitcoin/Ethereum wallet logic
- BIP39 support

## Typical runtime flow

1. The device boots and checks the secure element: it must be provisioned (`env:seprov_*`) and paired with this board, otherwise the device only reports that.
2. If no wallet is present, the user is prompted to create one.
3. A PIN (6 hex digits) is entered twice.
4. Entropy from the secure element RNG mixed with A0 noise becomes the 12-word mnemonic.
5. The root is sealed in the secure element; the EEPROM gets only public data (xpubs, public keys).
6. The 12 words are shown twice, then the PUK (8 hex digits): write both down.
7. The display rotates through address/QR views.
8. The host can query and request signatures at any time over the JSON protocol; anything sensitive is confirmed on the device (YES on the address screen skips to the next address).

## Bitcoin: native SegWit and PSBT

The BIP32 root is sealed in the secure element; the EEPROM holds the BIP84 account xpubs. The device then shows native SegWit (`bc1q…`) receive addresses, exports output descriptors, and signs PSBTs: every payment address and amount is shown on its own screen, followed by a summary with the fee and the change, which is only recognised as change if its derivation path, key and script all belong to this wallet. See `web-client/README.md` for the workflow with Sparrow / Bitcoin Core.

Host-supplied transactions and PSBTs are structurally validated before uBitcoin parses them: uBitcoin's PSBT parser corrupts memory on some malformed inputs (in fuzzing, 14 % of randomly corrupted PSBTs crashed it; none do after validation).

## Secure element, PIN and PUK

The ATECC508A (provisioned and locked once with `env:seprov_*`, see [docs/ATECC_PLAN.md](docs/ATECC_PLAN.md)) keeps the wallet secret:

- **PIN (6 hex digits)** for every signature. Inside the chip, 48 MAC rounds with a secret that never leaves it turn the PIN into the key that unlocks the root. Each check takes about 1 s, and every guess has to go through this chip. The chip itself refuses a wrong PIN. After a successful unlock the device warns about wrong attempts since the last unlock (from a monotonic counter). The seed is never wiped after wrong attempts.
- **PUK (8 hex digits)**, shown once after the 12 words at wallet creation. It is needed to change the PIN and for a factory reset (also when the PIN is forgotten). A new wallet on a chip that still holds a PUK asks for it.
- **Erase** (USB `erase`): confirm twice, then the PIN (erases the wallet, PIN and PUK stay) or the PUK (factory reset).
- **Change PIN** (USB `change_pin`): current PIN, PUK, new PIN twice.
- Entering digits: **NO** steps the shown digit (0-F), **YES** accepts it. Each digit starts at a random value, so counting presses reveals nothing. After the last digit, YES uses the digits and NO starts over.
- The seed only leaves the chip encrypted on the bus, and only for the right PIN; it is also encrypted on the MCU side with a key derived from the PIN. Private keys exist in RAM only while signing.
- Randomness (seed, PIN digit start, FIDO2 nonces, ECDSA blinding): the chip RNG mixed with A0 noise through SHA-256.

Storage format: no compatibility with older firmware. Wallets made by firmware before 0.5.0 are not recognised; create a new one (or restore the 12 words elsewhere).

## Device UI

- Main screen: wallet name, coin and address on the left, QR code on the right. **YES** = next coin (BTC, BTC testnet, ETH/EVM), **NO** = toggle a large view with the address in groups of 4 characters for comparison.
- After 1 minute untouched the coins rotate; after 3 minutes a screen saver hides the addresses (privacy, OLED burn-in). Any button wakes it.
- Backup words: one word per screen, YES = next, NO = previous; the list is shown twice (write down, then check).
- Prompts requested over USB (signing, address access, FIDO2) give up after 60 seconds without an answer.

## FIDO2 security key (2FA)

On the `adafruit_feather_m0` build the device also enumerates as a USB HID FIDO2 (CTAP2) authenticator, usable as a second factor in browsers via WebAuthn:

- Every registration and sign-in shows the site on the display and must be confirmed with **Yes** (No denies, 60 s timeout).
- Credentials are non-resident and stateless: the credential id the site stores is a nonce plus an HMAC tag, and the P-256 key is re-derived from a master secret. Credentials therefore survive power cycles and there is no slot limit, but passwordless "passkey" logins (resident keys) are not supported.
- The master secret is derived from the wallet seed when a wallet is generated (so the 12 words restore it) and sealed in the secure element. It is readable without the PIN (with the pairing secret), so the key works without the PIN. The signature counter is the secure element's monotonic counter 1: it can never go backwards.
- Storage is constant however many sites are registered. Each registration and each confirmed login advances the counter; silent browser probes do not. Erasing or regenerating the wallet creates a new master secret, which invalidates every existing registration, so keep the sites' backup codes.
- Only CTAP2 is implemented (no legacy CTAP1/U2F), there is no PIN/UV, and attestation is self-attestation.

## Build and run

This project uses PlatformIO.

From the project root:

```bash
pio run
```

To upload the firmware to the connected device, first **double-tap the reset button**: the bootloader starts and the board shows up as a new serial port. Then:

```bash
pio run --target upload --upload-port <bootloader port>
```

The wallet firmware ignores the Arduino "1200-baud touch" (opening and closing the port at 1200 baud), which would otherwise let any program on the computer restart the board into the bootloader and erase the start of the firmware. So only someone at the device can start a reflash (`sysTickHook()` in `src/main.cpp`).

The project is configured for boards such as:

- adafruit_feather_m0
- mzeroproUSB

## Notes and expectations

This is a prototype, not a production-grade security device. The code demonstrates embedded wallet generation, key derivation, and hardware-UI patterns rather than a full audited commercial wallet stack. It is best treated as a learning project, research prototype, or a platform for experimenting with secure embedded wallet design.

The code includes the core ideas behind a hardware wallet, but it should not be relied on for production-grade custody without a proper security review and a hardened storage/signing design.

## Repository summary

- firmware: src/
- device rendering: src/display/
- wallet logic: src/wallet.cpp
- configuration: platformio.ini
- mnemonic support: lib/bip39/
- tests: test/ (firmware host tests, `pio test -e native`) and web-client/test (`npm test`); see test/README

If you are exploring the project, start with [src/main.cpp](src/main.cpp), then read [src/wallet.cpp](src/wallet.cpp), and finally review the UI helpers in [src/display/display_fx.cpp](src/display/display_fx.cpp).
