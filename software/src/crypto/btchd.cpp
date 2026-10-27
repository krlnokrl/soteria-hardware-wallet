#include "btchd.h"

#include <stdio.h>
#include <string.h>
#include <Hash.h>
#include <utility/trezor/ecdsa.h>
#include <utility/trezor/secp256k1.h>

#define HARDENED 0x80000000UL

static const Network *net(bool testnet) {
    return testnet ? &Testnet : &Mainnet;
}

/* ------------------------------------------------------------------ */
/* Root encryption                                                     */
/* ------------------------------------------------------------------ */

// 64-byte keystream for (secret | chain code): SHA-512(PIN | label).
static void rootKeystream(const uint8_t pin[5], uint8_t ks[64]) {
    uint8_t buf[5 + 15];
    memcpy(buf, pin, 5);
    memcpy(buf + 5, "soteria-hd-root", 15);
    sha512(buf, sizeof(buf), ks);
}

void hdMakeRecord(const HDPrivateKey &root, const uint8_t pin[5], HdRecord &rec) {
    memset(&rec, 0, sizeof(rec));
    rec.magic = HD_RECORD_MAGIC;

    uint8_t plain[64], ks[64];
    root.getSecret(plain);
    memcpy(plain + 32, root.chainCode, 32);
    rootKeystream(pin, ks);
    for (int i = 0; i < 64; i++) rec.encRoot[i] = plain[i] ^ ks[i];
    memset(plain, 0, sizeof(plain));
    root.fingerprint(rec.fingerprint);

    for (int t = 0; t < 2; t++) {
        uint32_t path[3] = { HARDENED | 84, HARDENED | (uint32_t)t, HARDENED };
        HDPublicKey acct = root.derive(path, 3).xpub();
        acct.type = UNKNOWN_TYPE;   // plain xpub/tpub prefix, as descriptors expect
        acct.network = net(t);
        acct.xpub(rec.xpub[t], HD_XPUB_LEN);
    }
}

bool hdUnlock(const HdRecord &rec, const uint8_t pin[5], HDPrivateKey &root) {
    uint8_t plain[64], ks[64];
    rootKeystream(pin, ks);
    for (int i = 0; i < 64; i++) plain[i] = rec.encRoot[i] ^ ks[i];
    root = HDPrivateKey(plain, plain + 32);
    memset(plain, 0, sizeof(plain));
    uint8_t fp[4];
    root.fingerprint(fp);
    return memcmp(fp, rec.fingerprint, 4) == 0;
}

/* ------------------------------------------------------------------ */
/* Addresses and descriptors                                           */
/* ------------------------------------------------------------------ */

static HDPublicKey hdAccount(const HdRecord &rec, bool testnet) {
    return HDPublicKey(rec.xpub[testnet ? 1 : 0]);
}

size_t hdAddress(const HdRecord &rec, bool testnet, uint32_t change, uint32_t index,
                 char *out, size_t cap) {
    uint32_t path[2] = { change, index };
    HDPublicKey key = hdAccount(rec, testnet).derive(path, 2);
    int n = key.segwitAddress(out, cap, net(testnet));
    return n > 0 ? (size_t)n : 0;
}

size_t hdDescriptor(const HdRecord &rec, bool testnet, uint32_t change, char *out, size_t cap) {
    int n = snprintf(out, cap, "wpkh([%02x%02x%02x%02x/84h/%dh/0h]%s/%lu/*)",
                     rec.fingerprint[0], rec.fingerprint[1], rec.fingerprint[2], rec.fingerprint[3],
                     testnet ? 1 : 0, rec.xpub[testnet ? 1 : 0], (unsigned long)change);
    if (n <= 0 || (size_t)n + 10 > cap) return 0;
    char sum[10];
    if (descriptorChecksum(out, (size_t)n, sum, sizeof(sum)) != 8) return 0;
    out[n] = '#';
    memcpy(out + n + 1, sum, 8);
    out[n + 9] = 0;
    return (size_t)n + 9;
}

/* Bech32 (BIP173) / bech32m (BIP350) */

static const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t bech32Polymod(const uint8_t *v, size_t n) {
    static const uint32_t G[5] = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
    uint32_t chk = 1;
    for (size_t i = 0; i < n; i++) {
        uint8_t top = (uint8_t)(chk >> 25);
        chk = ((chk & 0x1ffffff) << 5) ^ v[i];
        for (int j = 0; j < 5; j++) if ((top >> j) & 1) chk ^= G[j];
    }
    return chk;
}

static size_t segwitEncode(const char *hrp, uint8_t version, const uint8_t *prog, size_t progLen,
                           char *out, size_t cap) {
    uint8_t data[1 + 64];                // witness version + 5-bit groups of <= 40 bytes
    size_t dl = 0;
    data[dl++] = version;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < progLen; i++) {
        acc = (acc << 8) | prog[i];
        bits += 8;
        while (bits >= 5) { bits -= 5; data[dl++] = (acc >> bits) & 31; }
    }
    if (bits) data[dl++] = (acc << (5 - bits)) & 31;

    size_t hl = strlen(hrp);
    if (hl + 1 + dl + 6 + 1 > cap) return 0;
    uint8_t v[2 * 8 + 1 + sizeof(data) + 6];
    size_t vl = 0;
    for (size_t i = 0; i < hl; i++) v[vl++] = (uint8_t)(hrp[i] >> 5);
    v[vl++] = 0;
    for (size_t i = 0; i < hl; i++) v[vl++] = (uint8_t)(hrp[i] & 31);
    memcpy(v + vl, data, dl); vl += dl;
    memset(v + vl, 0, 6);     vl += 6;
    uint32_t pm = bech32Polymod(v, vl) ^ (version == 0 ? 1 : 0x2bc830a3);

    size_t o = 0;
    memcpy(out, hrp, hl); o += hl;
    out[o++] = '1';
    for (size_t i = 0; i < dl; i++) out[o++] = BECH32_CHARSET[data[i]];
    for (int i = 0; i < 6; i++) out[o++] = BECH32_CHARSET[(pm >> (5 * (5 - i))) & 31];
    out[o] = 0;
    return o;
}

size_t btcScriptAddress(const Script &spk, bool testnet, char *out, size_t cap) {
    const uint8_t *s = spk.scriptArray;
    size_t n = spk.scriptLen;
    // witness program: OP_0 / OP_1..OP_16, then one push of 2..40 bytes
    if (n >= 4 && n <= 42 && (s[0] == 0x00 || (s[0] >= 0x51 && s[0] <= 0x60)) && s[1] == n - 2) {
        uint8_t version = s[0] == 0 ? 0 : (uint8_t)(s[0] - 0x50);
        if (version == 0 && n != 22 && n != 34) return 0;
        return segwitEncode(net(testnet)->bech32, version, s + 2, n - 2, out, cap);
    }
    if (spk.type() == P2PKH || spk.type() == P2SH) {
        return spk.address(out, cap, net(testnet));
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* PSBT                                                                */
/* ------------------------------------------------------------------ */

// True if d is m/84'/coin'/0'/change/index under our master fingerprint,
// derives (from the account xpub) to d's pubkey, and spk pays P2WPKH to it.
static bool ownedBy(const PSBTDerivation &d, const HdRecord &rec, const HDPublicKey &acct,
                    bool testnet, const Script &spk) {
    if (memcmp(d.fingerprint, rec.fingerprint, 4) != 0 || d.derivationLen != 5) return false;
    const uint32_t *p = d.derivation;
    if (p[0] != (HARDENED | 84) || p[1] != (HARDENED | (testnet ? 1 : 0)) || p[2] != HARDENED) return false;
    if (p[3] > 1 || p[4] >= HARDENED) return false;

    uint32_t tail[2] = { p[3], p[4] };
    HDPublicKey key = acct.derive(tail, 2);
    if (memcmp(key.point, d.pubkey.point, 64) != 0) return false;
    return Script(key, P2WPKH) == spk;
}

PsbtStatus psbtReview(const PSBT &psbt, const HdRecord &rec, bool testnet, PsbtSummary &sum) {
    memset(&sum, 0, sizeof(sum));
    const Tx &tx = psbt.tx;
    if (tx.outputsNumber > 64) return PSBT_TOO_MANY_OUTPUTS;
    HDPublicKey acct = hdAccount(rec, testnet);

    for (size_t i = 0; i < tx.inputsNumber; i++) {
        const PSBTInputMetadata &in = psbt.txInsMeta[i];
        if (in.txOut.amount == 0) return PSBT_MISSING_UTXO;
        sum.inputTotal += in.txOut.amount;
        for (size_t j = 0; j < in.derivationsLen; j++) {
            if (ownedBy(in.derivations[j], rec, acct, testnet, in.txOut.scriptPubkey)) {
                sum.ownInputs++;
                break;
            }
        }
    }
    if (sum.ownInputs == 0) return PSBT_NOT_OURS;

    uint64_t outTotal = 0;
    char addr[96];
    for (size_t i = 0; i < tx.outputsNumber; i++) {
        const TxOut &out = tx.txOuts[i];
        outTotal += out.amount;
        bool own = false;
        const PSBTOutputMetadata &meta = psbt.txOutsMeta[i];
        for (size_t j = 0; j < meta.derivationsLen && !own; j++) {
            own = ownedBy(meta.derivations[j], rec, acct, testnet, out.scriptPubkey);
        }
        if (own) {
            sum.ownOutputs |= 1ULL << i;
            sum.ownTotal += out.amount;
            continue;
        }
        bool opReturn = out.scriptPubkey.scriptLen > 0 && out.scriptPubkey.scriptArray[0] == 0x6a;
        if (!opReturn && btcScriptAddress(out.scriptPubkey, testnet, addr, sizeof(addr)) == 0) {
            return PSBT_UNDISPLAYABLE;
        }
        sum.sendTotal += out.amount;
    }
    if (outTotal > sum.inputTotal) return PSBT_BAD_AMOUNTS;
    sum.fee = sum.inputTotal - outTotal;
    return PSBT_OK;
}

uint8_t psbtSign(PSBT &psbt, const HDPrivateKey &root) {
    return psbt.sign(root);
}

/* ------------------------------------------------------------------ */
/* Structural validation of host data (before uBitcoin parses it)      */
/* ------------------------------------------------------------------ */

#define MAX_TX_INPUTS     32
#define MAX_TX_OUTPUTS    64
#define MAX_SCRIPT_LEN    10000
#define MAX_WITNESS_ITEMS 500

// Bounds-checked CompactSize; NULL if it runs past end.
static const uint8_t *readVarint(const uint8_t *p, const uint8_t *end, uint64_t *v) {
    if (p >= end) return NULL;
    uint8_t b = *p++;
    int n = b < 0xfd ? 0 : b == 0xfd ? 2 : b == 0xfe ? 4 : 8;
    if (n == 0) { *v = b; return p; }
    if (end - p < n) return NULL;
    uint64_t x = 0;
    for (int i = n - 1; i >= 0; i--) x = (x << 8) | p[i];
    *v = x;
    return p + n;
}

// Skip a length-prefixed byte string of at most maxLen bytes.
static const uint8_t *skipBytes(const uint8_t *p, const uint8_t *end, uint64_t maxLen, uint64_t *lenOut) {
    uint64_t n;
    p = readVarint(p, end, &n);
    if (!p || n > maxLen || n > (uint64_t)(end - p)) return NULL;
    if (lenOut) *lenOut = n;
    return p + n;
}

// Walk a serialized transaction. unsignedForm: the unsigned tx inside a
// PSBT (no witness serialization, empty scriptSigs).
static bool txWalk(const uint8_t *p, size_t len, bool unsignedForm, uint64_t *nIn, uint64_t *nOut) {
    const uint8_t *end = p + len;
    if (len < 10) return false;
    p += 4;                                         // version
    bool segwit = p[0] == 0x00 && p[1] == 0x01;
    if (segwit) {
        if (unsignedForm) return false;
        p += 2;
    }
    uint64_t ins, outs, n;
    if (!(p = readVarint(p, end, &ins)) || ins == 0 || ins > MAX_TX_INPUTS) return false;
    for (uint64_t i = 0; i < ins; i++) {
        if (end - p < 36) return false;
        p += 36;                                    // outpoint
        if (!(p = skipBytes(p, end, unsignedForm ? 0 : MAX_SCRIPT_LEN, NULL))) return false;
        if (end - p < 4) return false;
        p += 4;                                     // sequence
    }
    if (!(p = readVarint(p, end, &outs)) || outs == 0 || outs > MAX_TX_OUTPUTS) return false;
    for (uint64_t i = 0; i < outs; i++) {
        if (end - p < 8) return false;
        p += 8;                                     // amount
        if (!(p = skipBytes(p, end, MAX_SCRIPT_LEN, NULL))) return false;
    }
    if (segwit) {
        for (uint64_t i = 0; i < ins; i++) {
            if (!(p = readVarint(p, end, &n)) || n > MAX_WITNESS_ITEMS) return false;
            for (uint64_t j = 0; j < n; j++) {
                if (!(p = skipBytes(p, end, MAX_SCRIPT_LEN, NULL))) return false;
            }
        }
    }
    if (end - p != 4) return false;                 // locktime, nothing after it
    if (nIn) *nIn = ins;
    if (nOut) *nOut = outs;
    return true;
}

bool btcTxWellFormed(const uint8_t *raw, size_t len) {
    return txWalk(raw, len, false, NULL, NULL);
}

// One key-value pair of a PSBT map; keyLen == 0 marks the map separator.
struct PsbtPair {
    const uint8_t *start, *key, *val, *end;
    uint64_t keyLen, valLen;
};

static const uint8_t *psbtPair(const uint8_t *p, const uint8_t *end, PsbtPair &kv) {
    kv.start = p;
    if (!(p = readVarint(p, end, &kv.keyLen))) return NULL;
    if (kv.keyLen == 0) { kv.end = p; return p; }
    if (kv.keyLen > (uint64_t)(end - p)) return NULL;
    kv.key = p;
    p += kv.keyLen;
    if (!(p = readVarint(p, end, &kv.valLen)) || kv.valLen > (uint64_t)(end - p)) return NULL;
    kv.val = p;
    kv.end = p + kv.valLen;
    return kv.end;
}

// BIP32 derivation: key = type | 33-byte compressed pubkey (a real point),
// value = fingerprint | 1..16 path elements. The point is checked with
// trezor-crypto directly: uBitcoin's parser ignores a failed decompression
// and continues with uninitialised stack data.
static bool derivationOk(const PsbtPair &kv) {
    if (kv.keyLen != 34 || (kv.key[1] != 0x02 && kv.key[1] != 0x03)) return false;
    if (kv.valLen < 8 || kv.valLen > 4 + 16 * 4 || kv.valLen % 4) return false;
    curve_point pt;
    return ecdsa_read_pubkey(&secp256k1, kv.key + 1, &pt) == 1;
}

// TxOut: 8-byte amount and a script that fills the value exactly.
static bool txOutOk(const PsbtPair &kv) {
    if (kv.valLen < 9) return false;
    const uint8_t *end = kv.val + kv.valLen;
    return skipBytes(kv.val + 8, end, MAX_SCRIPT_LEN, NULL) == end;
}

bool psbtWellFormed(const uint8_t *raw, size_t len) {
    static const uint8_t MAGIC[5] = { 0x70, 0x73, 0x62, 0x74, 0xff };
    if (len < 5 || memcmp(raw, MAGIC, 5) != 0) return false;
    const uint8_t *p = raw + 5, *end = raw + len;
    PsbtPair kv;

    // Global map: the unsigned tx must come first (uBitcoin requires it).
    uint64_t nIn = 0, nOut = 0;
    bool first = true;
    for (;;) {
        if (!(p = psbtPair(p, end, kv))) return false;
        if (kv.keyLen == 0) break;
        if (first) {
            if (kv.keyLen != 1 || kv.key[0] != 0x00) return false;
            if (!txWalk(kv.val, kv.valLen, true, &nIn, &nOut)) return false;
            first = false;
        } else if (kv.key[0] == 0x00 || kv.key[0] == 0xFB) {
            return false;                           // duplicate tx / PSBTv2
        }
    }
    if (first) return false;

    for (uint64_t i = 0; i < nIn; i++) {
        for (;;) {
            if (!(p = psbtPair(p, end, kv))) return false;
            if (kv.keyLen == 0) break;
            switch (kv.key[0]) {
                case 0x00:                          // non-witness UTXO: a full transaction
                    if (kv.keyLen != 1 || !txWalk(kv.val, kv.valLen, false, NULL, NULL)) return false;
                    break;
                case 0x01:                          // witness UTXO
                    if (kv.keyLen != 1 || !txOutOk(kv)) return false;
                    break;
                case 0x02:                          // partial signature: already signed
                    return false;
                case 0x03:                          // sighash type: only SIGHASH_ALL
                    if (kv.keyLen != 1 || kv.valLen != 4 || kv.val[0] != 1 ||
                        kv.val[1] || kv.val[2] || kv.val[3]) return false;
                    break;
                case 0x04: case 0x05:               // redeem / witness script
                    if (kv.keyLen != 1 || kv.valLen > MAX_SCRIPT_LEN) return false;
                    break;
                case 0x06:
                    if (!derivationOk(kv)) return false;
                    break;
                default:                            // ignored by uBitcoin
                    break;
            }
        }
    }
    for (uint64_t i = 0; i < nOut; i++) {
        for (;;) {
            if (!(p = psbtPair(p, end, kv))) return false;
            if (kv.keyLen == 0) break;
            switch (kv.key[0]) {
                case 0x00: case 0x01:               // redeem / witness script
                    if (kv.keyLen != 1 || kv.valLen > MAX_SCRIPT_LEN) return false;
                    break;
                case 0x02:
                    if (!derivationOk(kv)) return false;
                    break;
                default:
                    break;
            }
        }
    }
    return p == end;
}

static size_t putVarint(uint8_t *out, uint64_t v) {
    if (v < 0xfd) { out[0] = (uint8_t)v; return 1; }
    out[0] = 0xfd;
    out[1] = (uint8_t)v;
    out[2] = (uint8_t)(v >> 8);
    return 3;
}

size_t psbtMergeSignatures(const uint8_t *raw, size_t len, const PSBT &psbt,
                           uint8_t *out, size_t cap) {
    const uint8_t *p = raw + 5, *end = raw + len;
    PsbtPair kv;
    size_t o = 0;
#define EMIT(src, n) do { if (o + (n) > cap) return 0; memcpy(out + o, (src), (n)); o += (n); } while (0)
    EMIT(raw, 5);
    do {                                            // global map, as is
        p = psbtPair(p, end, kv);
        EMIT(kv.start, (size_t)(kv.end - kv.start));
    } while (kv.keyLen != 0);

    for (size_t i = 0; i < psbt.tx.inputsNumber; i++) {
        for (;;) {                                  // input map minus its separator
            p = psbtPair(p, end, kv);
            if (kv.keyLen == 0) break;
            EMIT(kv.start, (size_t)(kv.end - kv.start));
        }
        const PSBTInputMetadata &in = psbt.txInsMeta[i];
        for (size_t j = 0; j < in.signaturesLen; j++) {
            uint8_t pair[1 + 1 + 33 + 3 + 72 + 1];
            size_t n = 0;
            pair[n++] = 34;                         // key: PSBT_IN_PARTIAL_SIG | pubkey
            pair[n++] = 0x02;
            in.signatures[j].pubkey.sec(pair + n, 33);
            n += 33;
            uint8_t der[72];
            size_t derLen = in.signatures[j].signature.der(der, sizeof(der));
            n += putVarint(pair + n, derLen + 1);
            memcpy(pair + n, der, derLen);
            n += derLen;
            pair[n++] = 0x01;                       // SIGHASH_ALL
            EMIT(pair, n);
        }
        uint8_t sep = 0;
        EMIT(&sep, 1);
    }
    EMIT(p, (size_t)(end - p));                     // output maps, as is
#undef EMIT
    return o;
}
