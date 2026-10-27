# Soteria Wallet

Soteria Wallet is a small hardware-wallet-style project built for the Adafruit Feather M0 / MZero Pro USB class of boards. The goal is to create a compact, self-contained device that can generate a seed, derive cryptocurrency keys, display wallet addresses as QR codes, and sign simple requests over USB without exposing the private key on a general-purpose computer.

This project is intentionally experimental and educational: it combines a low-power Arduino/PlatformIO firmware with an OLED display, a button interface, and a wallet generation flow modeled after Bitcoin and Ethereum key derivation.

## What the project is trying to achieve

The firmware aims to provide a minimal wallet experience in a secure-ish hardware form factor:

- Generate a wallet seed and derive keys for Bitcoin, Ethereum, FIDO U2F, and Bitcoin testnet
- Store keys in onboard EEPROM instead of in RAM only
- Protect the private material with a user-entered PIN before storing or using it
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
- EEPROM-backed wallet state and flags

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

- entropy generation via analog noise
- PIN entry and PIN verification
- BIP39 mnemonic generation
- HD private key derivation for BTC, BTCT, ETH, and U2F paths
- XOR-based key masking before saving to EEPROM
- wallet storage to SecureStorage
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

1. The device boots and checks whether a wallet has already been generated.
2. If no wallet is present, the user is prompted to create one.
3. A PIN is entered twice for verification.
4. Random entropy is collected and transformed into a mnemonic-based seed.
5. Hierarchical derivation creates keys for BTC, ETH, and testnet variants.
6. The resulting keys are XOR-masked and stored in EEPROM.
7. The display rotates through address/QR views.
8. The host can query and request signatures at any time over the JSON protocol; anything sensitive is confirmed on the device (YES on the address screen skips to the next address).

## Bitcoin: native SegWit and PSBT

Wallets created with this firmware also store the BIP32 root (XOR-encrypted with the PIN, like the other keys) and the BIP84 account xpubs. The device then shows native SegWit (`bc1q…`) receive addresses, exports output descriptors, and signs PSBTs: every payment address and amount is shown on its own screen, followed by a summary with the fee and the change, which is only recognised as change if its derivation path, key and script all belong to this wallet. See `web-client/README.md` for the workflow with Sparrow / Bitcoin Core.

Host-supplied transactions and PSBTs are structurally validated before uBitcoin parses them: uBitcoin's PSBT parser corrupts memory on some malformed inputs (in fuzzing, 14 % of randomly corrupted PSBTs crashed it; none do after validation).

Wallets created before SegWit support keep working with legacy addresses (`NO_SEGWIT` for the new commands) until they are erased and regenerated.

## Device UI

- Main screen: wallet name, coin and address on the left, QR code on the right. **YES** = next coin (BTC, BTC testnet, ETH/EVM), **NO** = toggle a large view with the address in groups of 4 characters for comparison.
- After 1 minute untouched the coins rotate; after 3 minutes a screen saver hides the addresses (privacy, OLED burn-in). Any button wakes it.
- Backup words: one word per screen, YES = next, NO = previous; the list is shown twice (write down, then check).
- Prompts requested over USB (signing, address access, FIDO2) give up after 60 seconds without an answer.

## FIDO2 security key (2FA)

On the `adafruit_feather_m0` build the device also enumerates as a USB HID FIDO2 (CTAP2) authenticator, usable as a second factor in browsers via WebAuthn:

- Every registration and sign-in shows the site on the display and must be confirmed with **Yes** (No denies, 60 s timeout).
- Credentials are non-resident and stateless: the credential id the site stores is a nonce plus an HMAC tag, and the P-256 key is re-derived from a master secret. Credentials therefore survive power cycles and there is no slot limit, but passwordless "passkey" logins (resident keys) are not supported.
- The master secret is derived from the wallet seed when a wallet is generated and stored in EEPROM key slot 4 without PIN encryption, so the key works without the PIN. The signature counter is persisted in EEPROM.
- Storage is constant: one 80-byte key slot plus a 4-byte counter, however many sites are registered. Each registration and each confirmed login rewrites the counter (4 bytes); silent browser probes do not. Erasing or regenerating the wallet creates a new master secret, which invalidates every existing registration, so keep the sites' backup codes.
- Only CTAP2 is implemented (no legacy CTAP1/U2F), there is no PIN/UV, and attestation is self-attestation.

Wallets generated with firmware before this change must be erased and regenerated: their EEPROM key data is corrupt (page-wrap bug), their 12 words did not restore the same keys in other BIP39 wallets, and they have no FIDO2 secret.

## Build and run

This project uses PlatformIO.

From the project root:

```bash
pio run
```

To upload the firmware to the connected device:

```bash
pio run --target upload
```

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
