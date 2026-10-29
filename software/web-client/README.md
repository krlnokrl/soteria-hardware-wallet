# Soteria Wallet – Web Serial Client

A browser client for the Soteria firmware's JSON protocol over USB serial.

## Prerequisites

- A browser with the **Web Serial API** (Chrome, Edge, Opera).
- The page must be served from **HTTPS** or **localhost**; `file://` does not work.

## Usage

1. Build and flash the firmware:
   ```sh
   cd software
   platformio run -t upload -e adafruit_feather_m0
   ```
2. Serve this folder and open `http://localhost:8000` in Chrome/Edge:
   ```sh
   cd software/web-client
   python3 -m http.server 8000      # Windows: py -m http.server 8000
   ```
3. Click **Connect** and choose the Soteria serial port. Device info loads automatically.

Requests that need the user (reading addresses the first time after power-on, renaming,
erasing, signing) show a yellow **Confirm on the device** banner until they are answered
with the device buttons.

## Build & send

`chain.js` (no dependencies, also loadable in Node) adds helpers to create and publish transactions:

- **Ethereum / EVM:** choose a network (12 presets with public [publicnode.com](https://publicnode.com)
  RPC endpoints, or any RPC URL), enter recipient and amount, optionally an ERC-20 contract
  (*Look up* reads its symbol and decimals). *Prepare* asks the node for nonce, fees
  (EIP-1559: max fee = 2 × base fee + tip) and gas (+20 % for contract calls), *Sign on device*
  sends the unsigned transaction to the device, *Broadcast* publishes the signed one
  (`eth_sendRawTransaction`) and links the explorer.
- **Bitcoin:** a PSBT signed by the device is finalized in the browser (native SegWit inputs:
  witness = signature + public key) into a raw transaction, shown with outputs, fee rate and txid,
  and broadcast through the [mempool.space](https://mempool.space) API (mainnet, testnet4,
  testnet3, signet). Creating the PSBT still needs a watch-only wallet with the coins' UTXOs:
  Sparrow, Electrum, Bitcoin Core or BlueWallet, using the descriptors from *Get xpubs*.

The RPC node and mempool.space see your addresses and IP address; run your own node for privacy.
Always try a testnet first. Broadcasting asks for confirmation and cannot be undone.

## Protocol (version 1)

USB CDC serial (baud rate irrelevant). The host must assert DTR (Web Serial: `setSignals`).
Both directions carry **one JSON object per line**, terminated by `\n` ("JSON Lines").

```
→ {"id": 7, "cmd": "sign_eth_tx", "tx": "02f86c01..."}
← {"event": "confirm_on_device", "id": 7, "cmd": "sign_eth_tx"}
← {"id": 7, "ok": true, "result": {"tx": "02f8af01...", "r": "…", "s": "…", "recid": 1}}

→ {"id": 8, "cmd": "set_name", "name": "my wallet"}
← {"id": 8, "ok": false, "error": {"code": "BAD_REQUEST", "msg": "name: 1-8 printable ASCII chars, no spaces"}}
```

- `id` is any JSON value chosen by the host and echoed in the reply and events.
- Requests are processed one at a time, in order; pipelining is allowed.
- Binary data is hex (an optional `0x` prefix is accepted on input; output is lowercase, no prefix);
  PSBTs are base64. Large payloads (`tx`, `psbt`, `hex`) must be plain strings without escapes.
- Limits: request line ≤ 3072 bytes, decoded payload ≤ 2048 bytes (see `info.limits`). A PSBT
  fits about 8 inputs with full previous transactions (`non_witness_utxo`), 13 with `witness_utxo` only.
- A request that needs the user blocks until the user answers on the device. Each prompt
  (and each PIN digit) gives up after 60 s without a button press (`USER_TIMEOUT`).
  `confirm_on_device` tells the host this has started.

### Commands

| cmd | params | result | device interaction |
|---|---|---|---|
| `help` | – | `commands` {name: description} | – |
| `ping` | – | `pong`, `uptime_ms` | – |
| `info` | – | `fw`, `proto`, `wallet`, `name`, `host_access`, `fido` {`supported`, `ready`, `counter`}, `secure_element` {`ready`, `serial`}, `limits` {`max_line`, `max_payload`, `free_ram`} | – |
| `addresses` | – | `btc`, `btc_testnet` (SegWit receive #0), `btc_legacy`, `btc_testnet_legacy`, `eth` (EIP-55) | allow once per power-on |
| `xpubs` | – | `fingerprint`, `btc` / `btc_testnet` {`path`, `xpub`, `receive`, `change`} (output descriptors with checksum) | allow once per power-on |
| `show_address` | `coin` (`btc`, `btc_testnet`, `eth`), `index`, `change` (0/1) | `address`, `confirmed` (user says it matches) | compare on screen |
| `pubkeys` | – | `btc`, `btc_testnet` (33-byte compressed), `eth` (65-byte uncompressed) | allow once per power-on |
| `set_name` | `name` (1–8 printable ASCII, no spaces) | `name` | confirm |
| `erase` | – | `erased` | confirm twice, then PIN (wallet erase) or PUK (factory reset) |
| `change_pin` | – | `changed` | confirm, current PIN, PUK, new PIN twice |
| `sign_psbt` | `psbt` (base64, unsigned), `testnet` (bool) | `psbt` (base64, input PSBT plus signatures), `signed_inputs`, `send`, `fee`, `change` (satoshis) | review each payment, fee/change summary, PIN |
| `sign_btc` | `tx` (unsigned legacy tx), `testnet` (bool) | `tx` (signed) | review each output, confirm, PIN |
| `sign_eth_tx` | `tx` (unsigned EIP-1559 `0x02…` or legacy EIP-155, any chain id) | `tx` (signed, ready to broadcast), `r`, `s`, `recid`, `chain`, `chain_name`, `erc20` {`type`, `token`, `to`/`spender`, `from`, `amount`} if recognised | review chain, recipient/value or token call, max fee, confirm, PIN |
| `sign_eth_message` | `message` (text) or `hex` | `signature` (65-byte r‖s‖v, v = 27/28), `r`, `s`, `v`, `recid` | review text, confirm, PIN |
| `sign_eth_hash` | `hash` (32 bytes) | like `sign_eth_message` | **blind** – confirm, PIN |

### Error codes

`BAD_JSON`, `BAD_REQUEST`, `UNKNOWN_CMD`, `TOO_LARGE`, `NO_WALLET`, `USER_REJECTED`,
`USER_TIMEOUT` (no button press within 60 s), `WRONG_PIN`, `INVALID_INPUT` (malformed/unsupported transaction),
`SECURE_ELEMENT` (secure element error or wallet data mismatch), `INTERNAL`.

### Text commands

For serial terminals, a line not starting with `{` is a text command, answered in JSON:
`HELP`, `PING`, `INFO`, `ADDRESS`, `PUBKEYS`, `NAME <name>`, `ERASE`,
`SIGN BTC <hex>`, `SIGN BTCT <hex>`, `SIGN ETH <hash>`, `SIGN ETHTX <hex>`.

## Notes

- **PSBT workflow:** `xpubs` → import the `receive` and `change` descriptors as a watch-only
  wallet (Sparrow: *New wallet → Import descriptor*; Bitcoin Core: `importdescriptors`) →
  create the transaction there and export the unsigned PSBT (Sparrow: *Finalize Transaction for
  Signing*, then *Save Transaction* for a .psbt file, or copy it as Base64; the raw transaction hex
  is **not** enough - it lacks input amounts and key paths) → *Sign PSBT* here (paste base64/hex
  or load the file; tick *testnet* for testnet4/testnet3/signet) → load the
  returned PSBT back into the wallet, finalize and broadcast. Only native SegWit (BIP84,
  `m/84'/0'/0'` and `m/84'/1'/0'` for testnet) single-signature inputs are signed; outputs may
  be any address type including Taproot. PSBTs that are already (partially) signed, PSBTv2 or
  with a sighash other than `SIGHASH_ALL` are refused.
- **ERC-20:** the device recognises `transfer`, `approve` and `transferFrom` calldata by
  selector and exact ABI shape. It cannot know whether the contract really is a token, nor its
  decimals, so amounts are in the token's base units (1 USDC = 1000000). Unlimited approvals
  are flagged.
- **EVM chains:** every EVM chain uses the same key and address. Known chain ids are shown by
  name with their native coin symbol (Ethereum, Sepolia, Holesky, Hoodi, Optimism, Arbitrum,
  Base, Linea, zkSync Era, Scroll, BNB Chain, Polygon, Avalanche, Gnosis, Celo, Cronos and their
  common testnets); others as `Chain <id>`.

- U2F/FIDO2 runs over USB HID, not serial, so it is not driven from this page; use a
  WebAuthn site (e.g. webauthn.io) instead. `info.fido` shows whether it is ready.
- Why JSON rather than binary: messages are small and infrequent, JSON is directly usable
  from JavaScript and readable in any serial terminal, and ArduinoJson costs ~15 KB of
  the 256 KB flash. Bulk data stays hex inside JSON. If throughput ever matters, CBOR in
  the same request/response/event envelope is the natural upgrade path.
