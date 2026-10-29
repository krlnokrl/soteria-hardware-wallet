#include "protocol.h"
#include "wallet.h"
#include "utils.h"
#include "crypto/btchd.h"
#include "crypto/ethtx.h"
#include <malloc.h>

SoteriaProtocol gProtocol;

static char    s_line[PROTO_MAX_LINE + 1];   // request line
static uint8_t s_raw[PROTO_MAX_RAW];         // decoded request payload
static uint8_t s_out[PROTO_MAX_OUT];         // signed transaction / PSBT

const SoteriaProtocol::Command SoteriaProtocol::commands[] = {
    { "help",             &SoteriaProtocol::cmdHelp,           false, "list commands" },
    { "ping",             &SoteriaProtocol::cmdPing,           false, "liveness check" },
    { "info",             &SoteriaProtocol::cmdInfo,           false, "firmware, wallet and FIDO2 state" },
    { "addresses",        &SoteriaProtocol::cmdAddresses,      true,  "first receive addresses (BTC SegWit, testnet, ETH)" },
    { "xpubs",            &SoteriaProtocol::cmdXpubs,          true,  "BIP84 account xpubs and output descriptors" },
    { "show_address",     &SoteriaProtocol::cmdShowAddress,    true,  "{coin, index, change}: verify an address on the device" },
    { "pubkeys",          &SoteriaProtocol::cmdPubkeys,        true,  "public keys (hex)" },
    { "set_name",         &SoteriaProtocol::cmdSetName,        true,  "{name}: rename wallet (<= 8 chars)" },
    { "erase",            &SoteriaProtocol::cmdErase,          true,  "erase wallet (confirm twice, then PIN or PUK on device)" },
    { "change_pin",       &SoteriaProtocol::cmdChangePin,      true,  "change the PIN (current PIN, PUK, new PIN on device)" },
    { "sign_psbt",        &SoteriaProtocol::cmdSignPsbt,       true,  "{psbt (base64), testnet}: sign SegWit PSBT" },
    { "sign_btc",         &SoteriaProtocol::cmdSignBtc,        true,  "{tx, testnet}: sign legacy P2PKH tx" },
    { "sign_eth_hash",    &SoteriaProtocol::cmdSignEthHash,    true,  "{hash}: blind-sign 32-byte hash" },
    { "sign_eth_tx",      &SoteriaProtocol::cmdSignEthTx,      true,  "{tx}: sign unsigned EIP-155/EIP-1559 tx" },
    { "sign_eth_message", &SoteriaProtocol::cmdSignEthMessage, true,  "{message | hex}: EIP-191 personal_sign" },
};

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static JsonObject succeed(JsonDocument &resp) {
    resp["ok"] = true;
    return resp["result"].to<JsonObject>();
}

static void fail(JsonDocument &resp, const char *code, const char *msg) {
    resp["ok"] = false;
    JsonObject e = resp["error"].to<JsonObject>();
    e["code"] = code;
    e["msg"] = msg;
}

static int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Strict hex decode of n chars with optional "0x"; returns the byte count,
// or -1 if the text is not hex, has odd length or exceeds cap.
static int hexDecode(const char *hex, size_t n, uint8_t *out, size_t cap) {
    if (!hex) return -1;
    if (n >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) { hex += 2; n -= 2; }
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexNibble(hex[2 * i]), lo = hexNibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(n / 2);
}

// Lowercase hex of data into out (2 * len + 1 bytes); returns out as
// char* so ArduinoJson copies it (out is reused between fields).
static char *hexEncode(const uint8_t *data, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 0x0F];
    }
    out[2 * len] = 0;
    return out;
}

// Add r, s, v (27 + recid), recid and the 65-byte r|s|v signature.
static void putEthSignature(JsonObject res, const uint8_t sig[65]) {
    char hex[131];
    uint8_t rsv[65];
    memcpy(rsv, sig, 64);
    rsv[64] = (uint8_t)(27 + sig[64]);
    res["signature"] = hexEncode(rsv, 65, hex);
    res["r"] = hexEncode(sig, 32, hex);
    res["s"] = hexEncode(sig + 32, 32, hex);
    res["v"] = 27 + sig[64];
    res["recid"] = sig[64];
}

// Bytes between the heap top and the stack, plus free blocks inside the
// heap: what is left for both.
extern "C" char *sbrk(int incr);
static int freeRam() {
    char top;
    return (int)(&top - sbrk(0)) + (int)mallinfo().fordblks;
}

/* In-place payload lookup: the string value of a top-level key, without
   copying it. Payload values (hex / base64) never contain escapes. */

static const char *skipWs(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

// p at an opening quote; returns the position after the closing one.
static const char *skipString(const char *p, const char *end) {
    for (p++; p < end; p++) {
        if (*p == '\\') { p++; continue; }
        if (*p == '"') return p + 1;
    }
    return nullptr;
}

static const char *skipValue(const char *p, const char *end) {
    if (p >= end) return nullptr;
    if (*p == '"') return skipString(p, end);
    if (*p == '{' || *p == '[') {
        int depth = 0;
        while (p < end) {
            if (*p == '"') {
                if (!(p = skipString(p, end))) return nullptr;
                continue;
            }
            if (*p == '{' || *p == '[') depth++;
            else if ((*p == '}' || *p == ']') && --depth == 0) return p + 1;
            p++;
        }
        return nullptr;
    }
    while (p < end && *p != ',' && *p != '}' && *p != ']' && *p != ' ') p++;   // number / literal
    return p;
}

static bool findPayload(const char *json, size_t len, const char *key, const char **val, size_t *vlen) {
    const char *p = skipWs(json, json + len), *end = json + len;
    size_t klen = strlen(key);
    if (p >= end || *p != '{') return false;
    p++;
    for (;;) {
        p = skipWs(p, end);
        if (p >= end || *p != '"') return false;
        const char *k = p + 1, *kEnd = skipString(p, end);
        if (!kEnd) return false;
        bool match = (size_t)(kEnd - 1 - k) == klen && memcmp(k, key, klen) == 0;
        p = skipWs(kEnd, end);
        if (p >= end || *p != ':') return false;
        p = skipWs(p + 1, end);
        if (match) {
            if (p >= end || *p != '"') return false;
            const char *v = p + 1, *vEnd = skipString(p, end);
            if (!vEnd) return false;
            *val = v;
            *vlen = (size_t)(vEnd - 1 - v);
            return memchr(v, '\\', *vlen) == nullptr;
        }
        if (!(p = skipValue(p, end))) return false;
        p = skipWs(p, end);
        if (p >= end || *p != ',') return false;
        p++;
    }
}

/* ------------------------------------------------------------------ */
/* Transport                                                           */
/* ------------------------------------------------------------------ */

void SoteriaProtocol::begin(Adafruit_SSD1306 &display, SecureStorage &eeprom) {
    _display = &display;
    _eeprom = &eeprom;
}

bool SoteriaProtocol::walletChanged() {
    bool c = _changed;
    _changed = false;
    return c;
}

void SoteriaProtocol::poll() {
    uint32_t last = millis();
    for (;;) {
        int c = Serial.read();
        if (c < 0) {
            // Mid-line the rest is normally already on its way; a partial
            // line otherwise waits for the next poll().
            if (_len == 0 || millis() - last > 20) return;
            continue;
        }
        last = millis();
        if (c == '\n' || c == '\r') {
            if (_overflow) {
                JsonDocument resp;
                resp["id"] = nullptr;
                fail(resp, "TOO_LARGE", "request line too long");
                serializeJson(resp, Serial);
                Serial.write('\n');
            } else if (_len > 0) {
                s_line[_len] = 0;
                handleLine();
            }
            _len = 0;
            _overflow = false;
            if (_changed) return;   // let the caller reload the wallet first
            continue;
        }
        if (_len < PROTO_MAX_LINE) s_line[_len++] = (char)c;
        else _overflow = true;
    }
}

void SoteriaProtocol::handleLine() {
    JsonDocument req;
    JsonDocument resp;
    _payload = nullptr;
    _payloadLen = 0;
    _bigKey = nullptr;
    if (s_line[0] == '{') {
        // Small fields go through ArduinoJson; the large payload stays in
        // s_line (a JSON copy of it would cost twice its size in heap).
        static const char *const PAYLOAD_KEYS[] = { "tx", "psbt", "hex" };
        for (const char *k : PAYLOAD_KEYS) {
            if (findPayload(s_line, _len, k, &_payload, &_payloadLen)) break;
        }
        JsonDocument filter;
        static const char *const SMALL_KEYS[] = {
            "id", "cmd", "testnet", "name", "hash", "message", "coin", "index", "change" };
        for (const char *k : SMALL_KEYS) filter[k] = true;
        DeserializationError err = deserializeJson(req, (const char *)s_line, _len,
                                                   DeserializationOption::Filter(filter));
        if (err) {
            resp["id"] = nullptr;
            fail(resp, "BAD_JSON", err.c_str());
        }
    } else if (!parseTextCommand(req)) {
        resp["id"] = nullptr;
        fail(resp, "UNKNOWN_CMD", "unknown text command, try HELP");
    }

    if (resp.isNull()) {
        resp["id"] = req["id"];
        const char *name = req["cmd"].as<const char *>();
        const Command *cmd = nullptr;
        for (const Command &c : commands) {
            if (name && strcmp(name, c.name) == 0) { cmd = &c; break; }
        }
        if (!cmd) {
            fail(resp, "UNKNOWN_CMD", "unknown cmd, try {\"cmd\":\"help\"}");
        } else if (cmd->needsWallet && !walletPresent()) {
            fail(resp, "NO_WALLET", "no wallet on the device");
        } else {
            // Nobody may be at the device: prompts give up after inactivity.
            setPromptTimeout(USER_CONFIRM_TIMEOUT_MS);
            _cmd = cmd->name;
            (this->*(cmd->fn))(req, resp);
            bool timedOut = promptTimedOut();   // read before resetting it
            setPromptTimeout(0);
            if (!resp["ok"].as<bool>() && timedOut) {
                resp.remove("error");
                fail(resp, "USER_TIMEOUT", "no answer on the device within 60 s");
            }
        }
    }
    writeResponse(resp);
}

// Mark a large binary result; writeResponse() streams it as the last
// field of "result" instead of copying it into the JSON document.
void SoteriaProtocol::streamResult(const char *key, const uint8_t *data, size_t len, bool base64) {
    _bigKey = key;
    _bigData = data;
    _bigLen = len;
    _bigBase64 = base64;
}

void SoteriaProtocol::writeResponse(JsonDocument &resp) {
    if (!_bigKey || !resp["ok"].as<bool>()) {
        serializeJson(resp, Serial);
        Serial.write('\n');
        return;
    }
    // "result" is the last member, so the text ends in "}}": write it up to
    // there, then the streamed field, then close both objects.
    char head[768];
    size_t n = serializeJson(resp, head, sizeof(head));
    if (n < 4 || n >= sizeof(head) - 1) {
        JsonDocument err;
        err["id"] = resp["id"];
        fail(err, "INTERNAL", "response too large");
        serializeJson(err, Serial);
        Serial.write('\n');
        return;
    }
    Serial.write((const uint8_t *)head, n - 2);
    if (head[n - 3] != '{') Serial.write(',');
    Serial.write('"');
    Serial.print(_bigKey);
    Serial.print("\":\"");
    char buf[72];
    const uint8_t *d = _bigData;
    size_t left = _bigLen;
    while (left) {
        // base64 in 48-byte groups (a multiple of 3: same as one encoding)
        size_t chunk = left > (_bigBase64 ? 48 : 32) ? (_bigBase64 ? 48 : 32) : left;
        size_t m = _bigBase64 ? toBase64(d, chunk, buf, sizeof(buf))
                              : strlen(hexEncode(d, chunk, buf));
        Serial.write((const uint8_t *)buf, m);
        d += chunk;
        left -= chunk;
    }
    Serial.print("\"}}\n");
}

// Terminal convenience: "INFO", "NAME bob", "SIGN BTC|BTCT|ETH|ETHTX <hex>".
bool SoteriaProtocol::parseTextCommand(JsonDocument &req) {
    char *save = nullptr;
    char *w0 = strtok_r(s_line, " \t", &save);
    char *w1 = strtok_r(nullptr, " \t", &save);
    char *w2 = strtok_r(nullptr, " \t", &save);
    if (!w0) return false;
    for (char *p = w0; *p; p++) *p = (char)tolower(*p);
    if (w1 && strcmp(w0, "sign") != 0) {
        if (strcmp(w0, "name") != 0) return false;
        req["cmd"] = "set_name";
        req["name"] = w1;
        return true;
    }
    if (strcmp(w0, "address") == 0) w0 = (char *)"addresses";
    if (strcmp(w0, "sign") == 0) {
        if (!w1 || !w2) return false;
        for (char *p = w1; *p; p++) *p = (char)tolower(*p);
        if (strcmp(w1, "btc") == 0 || strcmp(w1, "btct") == 0) {
            req["cmd"] = "sign_btc";
            _payload = w2;
            _payloadLen = strlen(w2);
            req["testnet"] = strcmp(w1, "btct") == 0;
        } else if (strcmp(w1, "eth") == 0) {
            req["cmd"] = "sign_eth_hash";
            req["hash"] = w2;
        } else if (strcmp(w1, "ethtx") == 0) {
            req["cmd"] = "sign_eth_tx";
            _payload = w2;
            _payloadLen = strlen(w2);
        } else {
            return false;
        }
        return true;
    }
    req["cmd"] = w0;
    return true;
}

// Tell the host the device now waits for the user (buttons / PIN).
void SoteriaProtocol::sendEvent(JsonDocument &resp, const char *event) {
    JsonDocument ev;
    ev["event"] = event;
    ev["id"] = resp["id"];
    ev["cmd"] = _cmd;
    serializeJson(ev, Serial);
    Serial.write('\n');
}

// Addresses and public keys identify the owner's funds, so the user
// grants read access once per power-on.
bool SoteriaProtocol::requireHostAccess(JsonDocument &resp) {
    if (_hostAccess) return true;
    sendEvent(resp, "confirm_on_device");
    _display->clearDisplay();
    _display->setCursor(0, 0);
    _display->setTextSize(1);
    _display->println("Allow computer to");
    _display->println("read your wallet");
    _display->println("addresses?");
    _hostAccess = askYesNo(*_display);
    return _hostAccess;
}

bool SoteriaProtocol::walletPresent() {
    return ::walletPresent(*_eeprom);
}

void SoteriaProtocol::failStatus(JsonDocument &resp, int status) {
    switch (status) {
        case WALLET_REJECTED:  fail(resp, "USER_REJECTED", "rejected on the device"); break;
        case WALLET_WRONG_PIN: fail(resp, "WRONG_PIN", "wrong PIN"); break;
        case WALLET_INVALID:   fail(resp, "INVALID_INPUT", "malformed or unsupported input"); break;
        case WALLET_TOO_LARGE: fail(resp, "TOO_LARGE", "result too large"); break;
        case WALLET_SE_ERROR:  fail(resp, "SECURE_ELEMENT", "secure element error or wallet data mismatch"); break;
        default:               fail(resp, "INTERNAL", "unexpected error"); break;
    }
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

void SoteriaProtocol::cmdHelp(JsonDocument &req, JsonDocument &resp) {
    JsonObject res = succeed(resp);
    JsonObject list = res["commands"].to<JsonObject>();
    for (const Command &c : commands) list[c.name] = c.help;
}

void SoteriaProtocol::cmdPing(JsonDocument &req, JsonDocument &resp) {
    JsonObject res = succeed(resp);
    res["pong"] = true;
    res["uptime_ms"] = millis();
}

void SoteriaProtocol::cmdInfo(JsonDocument &req, JsonDocument &resp) {
    JsonObject res = succeed(resp);
    res["fw"] = SOTERIA_FW_VERSION;
    res["proto"] = SOTERIA_PROTO_VERSION;
    bool wallet = walletPresent();
    res["wallet"] = wallet;
    if (wallet) {
        String name;
        _eeprom->getName(6, name);
        res["name"] = name;
    }
    res["host_access"] = _hostAccess;

    JsonObject fido = res["fido"].to<JsonObject>();
#ifdef SOTERIA_HAS_PLUGGABLE_USB
    fido["supported"] = true;
#else
    fido["supported"] = false;
#endif
    uint8_t secret[32];
    fido["ready"] = loadFidoSecret(secret);
    memset(secret, 0, sizeof(secret));
    uint32_t counter = 0;
    if (fidoCounter(counter, false)) fido["counter"] = counter;

    JsonObject se = res["secure_element"].to<JsonObject>();
    se["ready"] = gSe.ready();
    if (gSe.ready()) {
        char sn[19];
        se["serial"] = hexEncode(gSe.serial(), 9, sn);
    }

    JsonObject lim = res["limits"].to<JsonObject>();
    lim["max_line"] = PROTO_MAX_LINE;
    lim["max_payload"] = PROTO_MAX_RAW;
    lim["free_ram"] = freeRam();   // heap + stack headroom
}

void SoteriaProtocol::cmdAddresses(JsonDocument &req, JsonDocument &resp) {
    if (!requireHostAccess(resp)) { fail(resp, "USER_REJECTED", "access denied on the device"); return; }
    const WalletAddresses &a = walletAddresses(*_eeprom);   // cached: derivation takes seconds
    JsonObject res = succeed(resp);
    res["btc"] = a.btc;
    res["btc_testnet"] = a.btcTest;
    res["btc_legacy"] = a.btcLegacy;
    res["btc_testnet_legacy"] = a.btcTestLegacy;
    res["eth"] = a.eth;
}

void SoteriaProtocol::cmdPubkeys(JsonDocument &req, JsonDocument &resp) {
    if (!requireHostAccess(resp)) { fail(resp, "USER_REJECTED", "access denied on the device"); return; }
    HdRecord hd;
    if (!_eeprom->readHd(hd)) { fail(resp, "NO_WALLET", "no wallet"); return; }
    char hex[131];
    JsonObject res = succeed(resp);
    res["btc"] = hexEncode(hd.btcLegacy, 33, hex);
    res["btc_testnet"] = hexEncode(hd.btcTestLegacy, 33, hex);
    PublicKey pub(hd.eth);                 // ETH tooling wants 0x04 | x | y
    pub.compressed = false;
    uint8_t unc[65];
    pub.sec(unc, sizeof(unc));
    res["eth"] = hexEncode(unc, 65, hex);
}

void SoteriaProtocol::cmdSetName(JsonDocument &req, JsonDocument &resp) {
    const char *name = req["name"].as<const char *>();
    size_t n = name ? strlen(name) : 0;
    bool printable = n > 0 && n <= NAME_LENGTH;
    for (size_t i = 0; i < n && printable; i++) printable = name[i] > ' ' && name[i] < 127;
    if (!printable) { fail(resp, "BAD_REQUEST", "name: 1-8 printable ASCII chars, no spaces"); return; }

    sendEvent(resp, "confirm_on_device");
    _display->clearDisplay();
    _display->setCursor(0, 0);
    _display->setTextSize(1);
    _display->println("Rename wallet to");
    _display->println(name);
    if (!askYesNo(*_display)) { fail(resp, "USER_REJECTED", "rejected on the device"); return; }
    _eeprom->writeName(6, name);
    _changed = true;
    succeed(resp)["name"] = name;
}

void SoteriaProtocol::cmdErase(JsonDocument &req, JsonDocument &resp) {
    sendEvent(resp, "confirm_on_device");
    if (!eraseDevice(*_display, *_eeprom)) { fail(resp, "USER_REJECTED", "rejected on the device"); return; }
    _changed = true;
    _hostAccess = false;
    succeed(resp)["erased"] = true;
}

void SoteriaProtocol::cmdChangePin(JsonDocument &req, JsonDocument &resp) {
    sendEvent(resp, "confirm_on_device");
    WalletStatus st = changePin(*_display);
    if (st != WALLET_OK) { failStatus(resp, st); return; }
    succeed(resp)["changed"] = true;
}

void SoteriaProtocol::cmdSignBtc(JsonDocument &req, JsonDocument &resp) {
    int len = hexDecode(_payload, _payloadLen, s_raw, sizeof(s_raw));
    if (len <= 0) { fail(resp, "BAD_REQUEST", "tx: hex, max 2048 bytes"); return; }
    bool testnet = req["testnet"] | false;
    if (!btcTxWellFormed(s_raw, (size_t)len)) { fail(resp, "INVALID_INPUT", "malformed transaction"); return; }
    sendEvent(resp, "confirm_on_device");
    size_t outLen = 0;
    WalletStatus st = signBtcTx(*_display, *_eeprom, s_raw, (size_t)len, testnet, s_out, sizeof(s_out), &outLen);
    if (st != WALLET_OK) { failStatus(resp, st); return; }
    succeed(resp);
    streamResult("tx", s_out, outLen, false);
}

void SoteriaProtocol::cmdSignEthHash(JsonDocument &req, JsonDocument &resp) {
    uint8_t hash[32];
    const char *hashHex = req["hash"].as<const char *>();
    if (hexDecode(hashHex, hashHex ? strlen(hashHex) : 0, hash, sizeof(hash)) != 32) { fail(resp, "BAD_REQUEST", "hash: 32 bytes hex"); return; }
    sendEvent(resp, "confirm_on_device");
    uint8_t sig[65];
    WalletStatus st = signEthHash(*_display, *_eeprom, hash, sig);
    if (st != WALLET_OK) { failStatus(resp, st); return; }
    putEthSignature(succeed(resp), sig);
}

void SoteriaProtocol::cmdSignEthTx(JsonDocument &req, JsonDocument &resp) {
    int len = hexDecode(_payload, _payloadLen, s_raw, sizeof(s_raw));
    if (len <= 0) { fail(resp, "BAD_REQUEST", "tx: hex, max 2048 bytes"); return; }
    EthTx parsed;
    if (!ethTxParse(s_raw, (size_t)len, parsed)) {
        fail(resp, "INVALID_INPUT", "not an unsigned EIP-1559 or EIP-155 transaction");
        return;
    }
    sendEvent(resp, "confirm_on_device");
    uint8_t sig[65];
    size_t outLen = 0;
    WalletStatus st = signEthTx(*_display, *_eeprom, s_raw, (size_t)len, sig, s_out, sizeof(s_out), &outLen);
    if (st != WALLET_OK) { failStatus(resp, st); return; }
    JsonObject res = succeed(resp);
    char hex[65];
    res["r"] = hexEncode(sig, 32, hex);
    res["s"] = hexEncode(sig + 32, 32, hex);
    res["recid"] = sig[64];
    streamResult("tx", s_out, outLen, false);

    // What the device showed: chain and, if recognised, the ERC-20 call
    EthTx tx;
    ethTxParse(s_raw, (size_t)len, tx);
    const EthChain *chain = ethChainLookup(tx.chainId);
    res["chain"] = tx.chainId;
    if (chain) res["chain_name"] = chain->name;
    Erc20Call call;
    if (ethDecodeErc20(tx, call)) {
        static const char *const kinds[] = { "", "transfer", "approve", "transferFrom" };
        char addr[43], amount[84];
        JsonObject t = res["erc20"].to<JsonObject>();
        t["type"] = kinds[call.kind];
        ethAddressToString(tx.to, addr);
        t["token"] = (char *)addr;
        if (call.from) {
            ethAddressToString(call.from, addr);
            t["from"] = (char *)addr;
        }
        ethAddressToString(call.to, addr);
        t[call.kind == ERC20_APPROVE ? "spender" : "to"] = (char *)addr;
        ethFormatUnits(call.amount, 32, 0, amount, sizeof(amount));
        t["amount"] = (char *)amount;   // base units, as decimal text
    }
}

void SoteriaProtocol::cmdSignEthMessage(JsonDocument &req, JsonDocument &resp) {
    int len;
    if (req["message"].is<const char *>()) {
        const char *msg = req["message"].as<const char *>();
        len = (int)strlen(msg);
        if (len > PROTO_MAX_RAW) len = -1;
        else memcpy(s_raw, msg, len);
    } else {
        len = hexDecode(_payload, _payloadLen, s_raw, sizeof(s_raw));
    }
    if (len < 0) { fail(resp, "BAD_REQUEST", "message (text) or hex, max 2048 bytes"); return; }
    sendEvent(resp, "confirm_on_device");
    uint8_t sig[65];
    WalletStatus st = signEthMessage(*_display, *_eeprom, s_raw, (size_t)len, sig);
    if (st != WALLET_OK) { failStatus(resp, st); return; }
    putEthSignature(succeed(resp), sig);
}

void SoteriaProtocol::cmdXpubs(JsonDocument &req, JsonDocument &resp) {
    HdRecord hd;
    if (!_eeprom->readHd(hd)) { fail(resp, "NO_WALLET", "no wallet"); return; }
    if (!requireHostAccess(resp)) { fail(resp, "USER_REJECTED", "access denied on the device"); return; }
    JsonObject res = succeed(resp);
    char fp[9], desc[200];
    res["fingerprint"] = hexEncode(hd.fingerprint, 4, fp);
    for (int t = 0; t < 2; t++) {
        JsonObject acct = res[t ? "btc_testnet" : "btc"].to<JsonObject>();
        acct["path"] = t ? "m/84h/1h/0h" : "m/84h/0h/0h";
        acct["xpub"] = (char *)hd.xpub[t];
        hdDescriptor(hd, t, 0, desc, sizeof(desc));
        acct["receive"] = (char *)desc;
        hdDescriptor(hd, t, 1, desc, sizeof(desc));
        acct["change"] = (char *)desc;
    }
}

// Show one address on the device so the user can compare it with the one
// the computer displays (the computer could be compromised).
void SoteriaProtocol::cmdShowAddress(JsonDocument &req, JsonDocument &resp) {
    const char *coin = req["coin"] | "btc";
    uint32_t index = req["index"] | 0;
    uint32_t change = req["change"] | 0;
    bool testnet = strcmp(coin, "btc_testnet") == 0;
    char addr[96], title[22];

    if (strcmp(coin, "eth") == 0) {
        if (index != 0 || change != 0) { fail(resp, "BAD_REQUEST", "eth: only index 0"); return; }
        HdRecord hd;
        if (!_eeprom->readHd(hd)) { fail(resp, "NO_WALLET", "no wallet"); return; }
        ethAddressFromPub33(hd.eth, addr);
        snprintf(title, sizeof(title), "ETH/EVM address");
    } else if (testnet || strcmp(coin, "btc") == 0) {
        HdRecord hd;
        if (!_eeprom->readHd(hd)) { fail(resp, "NO_WALLET", "no wallet"); return; }
        if (index >= 0x80000000UL || change > 1) { fail(resp, "BAD_REQUEST", "index < 2^31, change 0 or 1"); return; }
        hdAddress(hd, testnet, change, index, addr, sizeof(addr));
        snprintf(title, sizeof(title), "%s %s #%lu", testnet ? "tBTC" : "BTC",
                 change ? "change" : "receive", (unsigned long)index);
    } else {
        fail(resp, "BAD_REQUEST", "coin: btc, btc_testnet or eth");
        return;
    }

    sendEvent(resp, "confirm_on_device");
    _display->clearDisplay();
    _display->setTextColor(WHITE);
    _display->setTextSize(1);
    _display->setCursor(0, 0);
    _display->println(title);
    _display->println();
    displayGrouped(*_display, addr);
    _display->println();
    _display->println("Same as on computer?");
    bool same = askYesNo(*_display);
    if (!same && promptTimedOut()) { fail(resp, "USER_REJECTED", "no answer"); return; }
    JsonObject res = succeed(resp);
    res["address"] = (char *)addr;
    res["confirmed"] = same;
}

void SoteriaProtocol::cmdSignPsbt(JsonDocument &req, JsonDocument &resp) {
    HdRecord hd;
    if (!_eeprom->readHd(hd)) { fail(resp, "NO_WALLET", "no wallet"); return; }
    bool testnet = req["testnet"] | false;
    size_t len = _payload ? fromBase64(_payload, _payloadLen, s_raw, sizeof(s_raw)) : 0;
    if (len == 0) { fail(resp, "BAD_REQUEST", "psbt: base64, max 2048 bytes"); return; }
    if (!psbtWellFormed(s_raw, len)) {
        fail(resp, "INVALID_INPUT", "malformed, PSBTv2 or already signed PSBT");
        return;
    }
    PSBT psbt;
    if (psbt.parse(s_raw, len) != len || !psbt.isValid()) {
        fail(resp, "INVALID_INPUT", "PSBT could not be parsed (non_witness_utxo must match its input)");
        return;
    }
    PsbtSummary sum;
    switch (psbtReview(psbt, hd, testnet, sum)) {
        case PSBT_OK: break;
        case PSBT_MISSING_UTXO:     fail(resp, "INVALID_INPUT", "an input has no UTXO data (amount unknown)"); return;
        case PSBT_NOT_OURS:         fail(resp, "INVALID_INPUT", "no input belongs to this wallet's BIP84 account (check testnet flag)"); return;
        case PSBT_BAD_AMOUNTS:      fail(resp, "INVALID_INPUT", "outputs exceed inputs"); return;
        case PSBT_UNDISPLAYABLE:    fail(resp, "INVALID_INPUT", "an output script cannot be shown as an address"); return;
        case PSBT_TOO_MANY_OUTPUTS: fail(resp, "INVALID_INPUT", "more than 64 outputs"); return;
    }

    sendEvent(resp, "confirm_on_device");
    uint8_t signedInputs = 0;
    WalletStatus st = signPsbt(*_display, psbt, hd, testnet, sum, &signedInputs);
    if (st != WALLET_OK) { failStatus(resp, st); return; }
    size_t outLen = psbtMergeSignatures(s_raw, len, psbt, s_out, sizeof(s_out));
    if (outLen == 0) { fail(resp, "TOO_LARGE", "signed PSBT too large"); return; }
    JsonObject res = succeed(resp);
    res["signed_inputs"] = signedInputs;
    res["fee"] = (double)sum.fee;        // satoshis (exact below 2^53)
    res["send"] = (double)sum.sendTotal;
    res["change"] = (double)sum.ownTotal;
    streamResult("psbt", s_out, outLen, true);
}
