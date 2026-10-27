#include "ethtx.h"
#include "keccak.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* RLP reader                                                          */
/* ------------------------------------------------------------------ */

struct RlpItem {
    const uint8_t* head;   // first byte of the encoding
    const uint8_t* data;   // payload
    size_t len;            // payload length
    const uint8_t* end;    // one past the encoding
    bool list;
};

static bool rlpItem(const uint8_t* p, const uint8_t* end, RlpItem& it) {
    if (p >= end) return false;
    uint8_t b = *p;
    it.head = p;
    size_t len;
    const uint8_t* data;
    if (b < 0x80) {                       // single byte is its own encoding
        it.list = false;
        data = p;
        len = 1;
    } else if (b <= 0xB7 || (b >= 0xC0 && b <= 0xF7)) {
        it.list = b >= 0xC0;
        data = p + 1;
        len = b - (it.list ? 0xC0 : 0x80);
    } else {                              // long form: length of length follows
        it.list = b >= 0xF8;
        size_t lenLen = b - (it.list ? 0xF7 : 0xB7);
        if (lenLen > 4 || (size_t)(end - p - 1) < lenLen) return false;
        len = 0;
        for (size_t i = 0; i < lenLen; i++) len = (len << 8) | p[1 + i];
        data = p + 1 + lenLen;
    }
    if (len > (size_t)(end - data)) return false;
    it.data = data;
    it.len = len;
    it.end = data + len;
    return true;
}

// A scalar field: a byte string of at most maxLen bytes.
static bool rlpScalar(const RlpItem& it, size_t maxLen) {
    return !it.list && it.len <= maxLen;
}

static uint64_t beToU64(const uint8_t* p, size_t len) {
    uint64_t v = 0;
    for (size_t i = 0; i < len; i++) v = (v << 8) | p[i];
    return v;
}

/* ------------------------------------------------------------------ */
/* RLP writer                                                          */
/* ------------------------------------------------------------------ */

static size_t rlpHeader(uint8_t* out, size_t len, bool list) {
    uint8_t base = list ? 0xC0 : 0x80;
    if (len <= 55) { out[0] = (uint8_t)(base + len); return 1; }
    uint8_t n = 0;
    for (size_t v = len; v; v >>= 8) n++;
    out[0] = (uint8_t)(base + 55 + n);
    for (uint8_t i = 0; i < n; i++) out[1 + i] = (uint8_t)(len >> (8 * (n - 1 - i)));
    return 1 + n;
}

// Integer from big-endian bytes, with leading zeros stripped.
static size_t rlpInt(uint8_t* out, const uint8_t* be, size_t len) {
    while (len && *be == 0) { be++; len--; }
    if (len == 1 && be[0] < 0x80) { out[0] = be[0]; return 1; }
    size_t h = rlpHeader(out, len, false);
    memcpy(out + h, be, len);
    return h + len;
}

/* ------------------------------------------------------------------ */
/* Transactions                                                        */
/* ------------------------------------------------------------------ */

bool ethTxParse(const uint8_t* raw, size_t len, EthTx& tx) {
    memset(&tx, 0, sizeof(tx));
    const uint8_t* p = raw;
    const uint8_t* end = raw + len;
    if (len == 0) return false;
    if (raw[0] == 0x02) {
        tx.type = 2;
        p++;
    } else if (raw[0] < 0xC0) {
        return false;                       // other typed txs (e.g. 0x01)
    }

    RlpItem list;
    if (!rlpItem(p, end, list) || !list.list || list.end != end) return false;

    RlpItem f[9];
    const uint8_t* q = list.data;
    for (int i = 0; i < 9; i++) {
        if (!rlpItem(q, list.end, f[i])) return false;   // also rejects < 9 fields
        q = f[i].end;
    }
    if (q != list.end) return false;                     // more than 9 fields

    // field indices per layout
    int iChain, iFee, iGas, iTo, iValue, iData;
    if (tx.type == 2) {
        iChain = 0; iFee = 3; iGas = 4; iTo = 5; iValue = 6; iData = 7;
        if (!f[8].list) return false;                    // accessList
        for (int i = 0; i < 7; i++) if (!rlpScalar(f[i], 32)) return false;
        tx.keep = f[0].head;
        tx.keepLen = (size_t)(f[8].end - f[0].head);
    } else {
        iChain = 6; iFee = 1; iGas = 2; iTo = 3; iValue = 4; iData = 5;
        for (int i = 0; i < 9; i++) if (!rlpScalar(f[i], i == 5 ? (size_t)-1 : 32)) return false;
        if (f[7].len != 0 || f[8].len != 0) return false;   // EIP-155: r = s = 0
        tx.keep = f[0].head;
        tx.keepLen = (size_t)(f[5].end - f[0].head);
    }
    if (f[iData].list) return false;

    // chain id: required (replay protection), small enough for v = 2*id+36
    if (f[iChain].len == 0 || f[iChain].len > 7) return false;
    tx.chainId = beToU64(f[iChain].data, f[iChain].len);
    if (tx.chainId == 0) return false;

    if (f[iTo].len != 0 && f[iTo].len != 20) return false;
    tx.to = f[iTo].len ? f[iTo].data : NULL;
    tx.value = f[iValue].data;
    tx.valueLen = (uint8_t)f[iValue].len;
    tx.gasLimit = f[iGas].data;
    tx.gasLimitLen = (uint8_t)f[iGas].len;
    tx.maxFee = f[iFee].data;
    tx.maxFeeLen = (uint8_t)f[iFee].len;
    tx.data = f[iData].data;
    tx.dataLen = f[iData].len;
    return true;
}

size_t ethTxEncodeSigned(const EthTx& tx, const uint8_t sig[65], uint8_t* out, size_t cap) {
    // v: yParity for type 2, chainId * 2 + 35 + recid for EIP-155
    uint8_t vBe[8];
    uint64_t v = tx.type == 2 ? sig[64] : tx.chainId * 2 + 35 + sig[64];
    for (int i = 0; i < 8; i++) vBe[i] = (uint8_t)(v >> (56 - 8 * i));

    uint8_t tail[3 * 33 + 9];
    size_t tailLen = 0;
    tailLen += rlpInt(tail + tailLen, vBe, 8);
    tailLen += rlpInt(tail + tailLen, sig, 32);
    tailLen += rlpInt(tail + tailLen, sig + 32, 32);

    size_t payload = tx.keepLen + tailLen;
    uint8_t hdr[9];
    size_t hdrLen = rlpHeader(hdr, payload, true);
    size_t total = (tx.type == 2 ? 1 : 0) + hdrLen + payload;
    if (total > cap) return 0;

    uint8_t* p = out;
    if (tx.type == 2) *p++ = 0x02;
    memcpy(p, hdr, hdrLen);       p += hdrLen;
    memcpy(p, tx.keep, tx.keepLen); p += tx.keepLen;
    memcpy(p, tail, tailLen);     p += tailLen;
    return total;
}

/* ------------------------------------------------------------------ */
/* 256-bit helpers (little-endian 32-bit limbs)                         */
/* ------------------------------------------------------------------ */

static void beToLimbs(const uint8_t* be, size_t len, uint32_t limbs[8]) {
    memset(limbs, 0, 8 * sizeof(uint32_t));
    for (size_t i = 0; i < len && i < 32; i++) {
        size_t bit = 8 * (len - 1 - i);
        limbs[bit / 32] |= (uint32_t)be[i] << (bit % 32);
    }
}

bool ethTxMaxFee(const EthTx& tx, uint8_t out[32]) {
    uint32_t a[8], b[8];
    beToLimbs(tx.gasLimit, tx.gasLimitLen, a);
    beToLimbs(tx.maxFee, tx.maxFeeLen, b);
    uint32_t r[16] = {0};
    for (int i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t t = (uint64_t)a[i] * b[j] + r[i + j] + carry;
            r[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        r[i + 8] = (uint32_t)carry;
    }
    for (int i = 8; i < 16; i++) if (r[i]) return false;
    for (int i = 0; i < 32; i++) out[31 - i] = (uint8_t)(r[i / 4] >> (8 * (i % 4)));
    return true;
}

size_t ethFormatUnits(const uint8_t* be, size_t len, uint8_t decimals, char* out, size_t cap) {
    uint32_t n[8];
    beToLimbs(be, len, n);

    // Collect decimal digits, least significant first (2^256 < 10^78).
    char digits[80];
    int nd = 0;
    bool zero;
    do {
        uint64_t rem = 0;
        zero = true;
        for (int i = 7; i >= 0; i--) {
            uint64_t cur = (rem << 32) | n[i];
            n[i] = (uint32_t)(cur / 10);
            rem = cur % 10;
            if (n[i]) zero = false;
        }
        digits[nd++] = (char)('0' + rem);
    } while (!zero);
    while (nd <= decimals) digits[nd++] = '0';   // at least one integer digit

    // Drop trailing fractional zeros.
    int fracStart = 0;
    while (fracStart < decimals && digits[fracStart] == '0') fracStart++;

    size_t need = (size_t)(nd - decimals) + (fracStart < decimals ? 1 + (decimals - fracStart) : 0) + 1;
    if (need > cap) return 0;
    size_t o = 0;
    for (int i = nd - 1; i >= decimals; i--) out[o++] = digits[i];
    if (fracStart < decimals) {
        out[o++] = '.';
        for (int i = decimals - 1; i >= fracStart; i--) out[o++] = digits[i];
    }
    out[o] = 0;
    return o;
}

void ethPersonalMessageHash(const uint8_t* msg, size_t len, uint8_t hash[32]) {
    static const char prefix[] = "\x19" "Ethereum Signed Message:\n";
    char lenStr[12];
    int ln = 0;
    char rev[12];
    size_t v = len;
    do { rev[ln++] = (char)('0' + v % 10); v /= 10; } while (v);
    for (int i = 0; i < ln; i++) lenStr[i] = rev[ln - 1 - i];

    size_t pl = sizeof(prefix) - 1;
    size_t total = pl + ln + len;
    uint8_t* buf = (uint8_t*)malloc(total);
    if (!buf) { memset(hash, 0, 32); return; }
    memcpy(buf, prefix, pl);
    memcpy(buf + pl, lenStr, ln);
    memcpy(buf + pl + ln, msg, len);
    keccak256(hash, buf, total);
    free(buf);
}

/* ------------------------------------------------------------------ */
/* ERC-20                                                              */
/* ------------------------------------------------------------------ */

// An ABI-encoded address: 12 zero bytes, then the 20-byte address.
static bool abiAddress(const uint8_t* word, const uint8_t** addr) {
    for (int i = 0; i < 12; i++) if (word[i] != 0) return false;
    *addr = word + 12;
    return true;
}

bool ethDecodeErc20(const EthTx& tx, Erc20Call& call) {
    memset(&call, 0, sizeof(call));
    if (!tx.to || tx.dataLen < 4) return false;
    const uint8_t* d = tx.data;
    const uint8_t* args = d + 4;
    size_t argLen = tx.dataLen - 4;
    static const uint8_t TRANSFER[4]      = { 0xa9, 0x05, 0x9c, 0xbb };
    static const uint8_t APPROVE[4]       = { 0x09, 0x5e, 0xa7, 0xb3 };
    static const uint8_t TRANSFER_FROM[4] = { 0x23, 0xb8, 0x72, 0xdd };

    if ((memcmp(d, TRANSFER, 4) == 0 || memcmp(d, APPROVE, 4) == 0) && argLen == 64) {
        if (!abiAddress(args, &call.to)) return false;
        call.amount = args + 32;
        call.kind = memcmp(d, TRANSFER, 4) == 0 ? ERC20_TRANSFER : ERC20_APPROVE;
        return true;
    }
    if (memcmp(d, TRANSFER_FROM, 4) == 0 && argLen == 96) {
        if (!abiAddress(args, &call.from) || !abiAddress(args + 32, &call.to)) return false;
        call.amount = args + 64;
        call.kind = ERC20_TRANSFER_FROM;
        return true;
    }
    return false;
}

bool ethIsMaxUint256(const uint8_t v[32]) {
    for (int i = 0; i < 32; i++) if (v[i] != 0xFF) return false;
    return true;
}

/* ------------------------------------------------------------------ */
/* EVM chains                                                          */
/* ------------------------------------------------------------------ */

static const EthChain s_chains[] = {
    { 1,        "Ethereum",         "ETH"  },
    { 11155111, "Sepolia",          "ETH"  },
    { 17000,    "Holesky",          "ETH"  },
    { 560048,   "Hoodi",            "ETH"  },
    { 10,       "Optimism",         "ETH"  },
    { 11155420, "OP Sepolia",       "ETH"  },
    { 42161,    "Arbitrum One",     "ETH"  },
    { 421614,   "Arbitrum Sepolia", "ETH"  },
    { 8453,     "Base",             "ETH"  },
    { 84532,    "Base Sepolia",     "ETH"  },
    { 59144,    "Linea",            "ETH"  },
    { 324,      "zkSync Era",       "ETH"  },
    { 534352,   "Scroll",           "ETH"  },
    { 56,       "BNB Chain",        "BNB"  },
    { 97,       "BNB Testnet",      "tBNB" },
    { 137,      "Polygon",          "POL"  },
    { 80002,    "Polygon Amoy",     "POL"  },
    { 43114,    "Avalanche C",      "AVAX" },
    { 43113,    "Avalanche Fuji",   "AVAX" },
    { 100,      "Gnosis",           "xDAI" },
    { 42220,    "Celo",             "CELO" },
    { 25,       "Cronos",           "CRO"  },
};

const EthChain* ethChainLookup(uint64_t id) {
    for (size_t i = 0; i < sizeof(s_chains) / sizeof(s_chains[0]); i++) {
        if (s_chains[i].id == id) return &s_chains[i];
    }
    return NULL;
}
