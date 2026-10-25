# Soteria Wallet – Web Serial Debug Client

A small browser-based client to test and debug the Soteria hardware wallet firmware over USB Serial.

## Prerequisites

- A modern browser with **Web Serial API** support (Chrome, Edge, Opera).
- The page must be served over **HTTPS** or **localhost** (secure context). Opening `index.html` directly as `file://` will not work.

## Usage

1. Build and flash the firmware to your SAMD21 board:
   ```sh
   cd software
   platformio run -e adafruit_feather_m0
   platformio run -t upload -e adafruit_feather_m0
   ```

2. Serve this folder locally. From the repository root:
   ```sh
   cd software/web-client
   python3 -m http.server 8000
   # (Windows: py -m http.server 8000)
   ```

3. Open `http://localhost:8000` in Chrome/Edge.

4. Click **Connect** and select your Soteria device's serial port.

5. Use the buttons to send commands:
   - `ADDRESS` – prints BTC / BTCtest / ETH addresses
   - `NAME <name>` – sets the wallet name (max 8 chars)
   - `ERASE` – wipes all stored keys (requires two confirmations on device)
   - `Sign BTC / BTC Testnet / ETH hash` – sends `SIGN <network> <hex>` to the device

## Serial protocol

The firmware speaks plain text over USB Serial at **115200 baud**. Commands are one per line:

| Command | Meaning |
|---------|---------|
| `ADDRESS` | List BTC, BTCtest, ETH addresses |
| `NAME <name>` | Set wallet name |
| `ERASE` | Erase all keys (device confirms twice) |
| `SIGN BTC <hex>` | Sign a raw Bitcoin transaction |
| `SIGN BTCT <hex>` | Sign a raw Bitcoin testnet transaction |
| `SIGN ETH <64-hex>` | Sign a 32-byte Keccak-256 hash (Ethereum) |

## Notes

- Web Serial requires a user gesture (clicking **Connect**) before the port can be opened.
- The ETH signing path expects the host to compute `keccak256(RLP(unsigned_tx_with_chainId))` and send only the 32-byte hash. The device returns `R`, `S`, and `V` components over Serial and as QR codes on the OLED.
- U2F/CTAPHID is implemented over USB HID, not Serial, so it is not exercisable from this page.
