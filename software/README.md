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
- USB serial interface for interactive wallet actions
- EEPROM-backed wallet state and flags

## Code structure

The project is organized around a small embedded firmware layout:

### src/main.cpp
This is the main application loop. It is responsible for:

- setting up the display and GPIO
- checking whether a wallet already exists
- prompting the user to generate one if none is present
- showing wallet addresses in a rotating display loop
- handling a USB console flow for commands like ADDRESS, NAME, ERASE, and SIGN

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

### src/menu.cpp
This file contains the menu rendering functions used by the wallet screen, such as:

- a wallet banner
- address view rendering
- USB menu views
- command list display helpers

It is a presentation layer for the embedded UI.

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
8. Pressing the relevant button can trigger a USB session to sign or query the wallet state.

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
- tests: test/

If you are exploring the project, start with [src/main.cpp](src/main.cpp), then read [src/wallet.cpp](src/wallet.cpp), and finally review the UI helpers in [src/display/display_fx.cpp](src/display/display_fx.cpp).
