// Wallet sanity tests: key derivation, addresses and signatures against
// independent reference values (BIP39/BIP44/BIP84 test vectors, embit,
// eth-account). Mnemonic: the standard "abandon ... about" test vector.
#include <unity.h>

#include <string>
#include <Bitcoin.h>
#include <PSBT.h>
#include <Hash.h>
#include <Conversion.h>
#include "bip39.h"
#include "crypto/btchd.h"
#include "crypto/ethtx.h"
#include "crypto/keccak.h"
#include "utils.h"

static const char *MNEMONIC =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

static HDPrivateKey root() { return HDPrivateKey(MNEMONIC, strlen(MNEMONIC), "", 0); }

static std::string hex(const uint8_t *d, size_t n) {
    static const char *digits = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) { s += digits[d[i] >> 4]; s += digits[d[i] & 15]; }
    return s;
}

static int nibble(char c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; }

static size_t unhex(const char *h, uint8_t *out, size_t cap) {
    size_t n = strlen(h) / 2;
    TEST_ASSERT_TRUE(n <= cap);
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(nibble(h[2 * i]) << 4 | nibble(h[2 * i + 1]));
    return n;
}

void setUp(void) {}
void tearDown(void) {}

// BIP39: entropy -> words (lib/bip39), as generateWallet() uses it
static void test_bip39_words(void) {
    struct { uint8_t byte; const char *words; } v[] = {
        { 0x00, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" },
        { 0x7f, "legal winner thank year wave sausage worth useful legal winner thank yellow" },
        { 0x80, "letter advice cage absurd amount doctor acoustic avoid letter advice cage above" },
        { 0xff, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong" },
    };
    for (auto &t : v) {
        uint8_t entropy[16];
        memset(entropy, t.byte, sizeof(entropy));
        std::string words = seedToWords(entropy, 16);
        while (!words.empty() && words.back() == ' ') words.pop_back();   // as generateWallet() trims
        TEST_ASSERT_EQUAL_STRING(t.words, words.c_str());
    }
}

// BIP84 native SegWit accounts, descriptor, root as sealed in the
// secure element
static void test_bip84_addresses_and_descriptor(void) {
    HdRecord rec;
    hdMakeRecord(root(), rec);
    char buf[256];
    TEST_ASSERT_EQUAL_STRING("73c5da0a", hex(rec.fingerprint, 4).c_str());
    hdAddress(rec, false, 0, 0, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", buf);   // BIP84 vector
    hdAddress(rec, false, 1, 0, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", buf);   // BIP84 vector
    hdAddress(rec, true, 0, 0, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", buf);
    hdDescriptor(rec, false, 0, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHw"
                             "CD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#afwvtk2s", buf);

    uint8_t bytes[64];
    hdRootBytes(root(), bytes);
    HDPrivateKey unlocked;
    TEST_ASSERT_TRUE(hdRootFromBytes(bytes, rec, unlocked));
    uint8_t again[64];
    hdRootBytes(unlocked, again);
    TEST_ASSERT_EQUAL_MEMORY(bytes, again, 64);
    bytes[5] ^= 1;                   // another root: fingerprint differs
    TEST_ASSERT_FALSE(hdRootFromBytes(bytes, rec, unlocked));
}

// BIP44 legacy BTC and Ethereum (keccak + EIP-55) addresses
static void test_bip44_btc_and_eth_addresses(void) {
    HDPrivateKey btc = root().hardenedChild(44).hardenedChild(0).hardenedChild(0).child(0).child(0);
    char buf[64];
    btc.publicKey().legacyAddress(buf, sizeof(buf), &Mainnet);
    TEST_ASSERT_EQUAL_STRING("1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", buf);

    HDPrivateKey eth = root().hardenedChild(44).hardenedChild(60).hardenedChild(0).child(0).child(0);
    PublicKey pub = eth.publicKey();
    pub.compressed = false;
    uint8_t sec[65];
    pub.sec(sec, sizeof(sec));
    char addr[43];
    ethAddressFromPubkey(sec, addr);
    TEST_ASSERT_EQUAL_STRING("0x9858EfFD232B4033E47d90003D41EC34EcaEda94", addr);

    uint8_t h[32];
    keccak256(h, (const uint8_t *)"", 0);
    TEST_ASSERT_EQUAL_STRING("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", hex(h, 32).c_str());
}

// EIP-1559 transaction signed exactly like eth-account (RFC 6979)
static void test_eth_transaction_signature(void) {
    uint8_t raw[256], out[300], sig[65], hash[32];
    size_t len = unhex("02ef010584773594008509502f9000825208943535353535353535353535353535353535353535"
                       "872386f26fc1000080c0", raw, sizeof(raw));
    EthTx tx;
    TEST_ASSERT_TRUE(ethTxParse(raw, len, tx));
    TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)tx.chainId);

    HDPrivateKey eth = root().hardenedChild(44).hardenedChild(60).hardenedChild(0).child(0).child(0);
    keccak256(hash, raw, len);
    eth.sign(hash).bin(sig, 65);
    size_t n = ethTxEncodeSigned(tx, sig, out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING(
        "02f872010584773594008509502f9000825208943535353535353535353535353535353535353535872386f26fc1000080c0"
        "01a0039dc50f8e82d1dde445afb58deb12ad1eafb9a67be987a4b34d5534b9687755a041040764ac5db3bae73a49499eae66"
        "71d406f7e7bf21dd2dc60b8ee09c32c460", hex(out, n).c_str());
}

// ERC-20 transfer recognised, chain name from the table
static void test_erc20_and_chain(void) {
    uint8_t raw[256];
    size_t len = unhex("02f8708189808506fc23ac00850df847580083013880943c499c542cef5e3811e1192ce70d8cc03d5c3359"
                       "80b844a9059cbb0000000000000000000000002222222222222222222222222222222222222222000000"
                       "00000000000000000000000000000000000000000000000000000f4240c0", raw, sizeof(raw));
    EthTx tx;
    TEST_ASSERT_TRUE(ethTxParse(raw, len, tx));
    Erc20Call call;
    TEST_ASSERT_TRUE(ethDecodeErc20(tx, call));
    TEST_ASSERT_EQUAL_INT(ERC20_TRANSFER, call.kind);
    char amount[84];
    ethFormatUnits(call.amount, 32, 6, amount, sizeof(amount));
    TEST_ASSERT_EQUAL_STRING("1", amount);   // 1 USDC
    TEST_ASSERT_EQUAL_STRING("Polygon", ethChainLookup(tx.chainId)->name);
}

// PSBT (from embit): review, sign, verify the signature, merge
static const char *PSBT_B64 =
    "cHNidP8BAH0CAAAAAa3gZG7pcw5OhXvkIstMRHdD8yvBNNYbhwZ9g5Ch/sCYAQAAAAD9////AmDqAAAAAAAAIlEgPyZjGkUPVotnCYze"
    "LRqQ5HlKzbz09lXytJEZM+461tpYmAAAAAAAABYAFD40mF3Kb93J+zaZQOTH2OKHP1KcAAAAAAABAR+ghgEAAAAAABYAFMDOvNbD08qM"
    "ddxexi6+VTMO+RDiIgYDMNVP0N1CCm5fjTYk9fNILK41D3nV8HU79b7vnC2RrzwYc8XaClQAAIAAAACAAAAAgAAAAAAAAAAAAAAiAgMC"
    "UySIjkKauOPbrx94AmSLnNAem0GEhcX6TBubVwDhphhzxdoKVAAAgAAAAIAAAACAAQAAAAAAAAAA";

static void test_psbt_review_and_sign(void) {
    static uint8_t raw[1024], merged[1500];
    size_t len = fromBase64(PSBT_B64, strlen(PSBT_B64), raw, sizeof(raw));
    TEST_ASSERT_TRUE(len > 0);
    TEST_ASSERT_TRUE(psbtWellFormed(raw, len));
    PSBT psbt;
    TEST_ASSERT_EQUAL_UINT32(len, psbt.parse(raw, len));

    HdRecord rec;
    hdMakeRecord(root(), rec);
    PsbtSummary sum;
    TEST_ASSERT_EQUAL_INT(PSBT_OK, psbtReview(psbt, rec, false, sum));
    TEST_ASSERT_EQUAL_UINT32(1000, (uint32_t)sum.fee);
    TEST_ASSERT_EQUAL_UINT32(60000, (uint32_t)sum.sendTotal);
    TEST_ASSERT_EQUAL_UINT32(39000, (uint32_t)sum.ownTotal);   // change recognised...
    TEST_ASSERT_EQUAL_UINT32(0b10, (uint32_t)sum.ownOutputs);  // ...as output 1
    char addr[96];
    btcScriptAddress(psbt.tx.txOuts[0].scriptPubkey, false, addr, sizeof(addr));
    TEST_ASSERT_EQUAL_STRING("bc1p8unxxxj9patgkecf3n0z6x5su3u54ndu7nm9tu45jyvn8m366mdqsef3ta", addr);   // bech32m

    TEST_ASSERT_EQUAL_UINT8(1, psbtSign(psbt, root()));
    PSBTPartialSignature &ps = psbt.txInsMeta[0].signatures[0];
    uint8_t h[32];
    psbt.tx.sigHashSegwit(h, 0, ps.pubkey.script(), 100000);   // BIP143, P2WPKH script code
    TEST_ASSERT_TRUE(ps.pubkey.verify(ps.signature, h));

    size_t m = psbtMergeSignatures(raw, len, psbt, merged, sizeof(merged));
    TEST_ASSERT_TRUE(m > len);
    PSBT signedPsbt;
    TEST_ASSERT_EQUAL_UINT32(m, signedPsbt.parse(merged, m));
    TEST_ASSERT_EQUAL_UINT8(1, signedPsbt.txInsMeta[0].signaturesLen);
    TEST_ASSERT_EQUAL_UINT32(100000, (uint32_t)signedPsbt.txInsMeta[0].txOut.amount);   // UTXO kept
    TEST_ASSERT_FALSE(psbtWellFormed(merged, m));   // already signed: refused again
}

// Host data is validated before uBitcoin parses it (its parser is not
// memory-safe on malformed input): truncated / garbage PSBTs are refused.
static void test_psbt_malformed_refused(void) {
    static uint8_t raw[1024];
    size_t len = fromBase64(PSBT_B64, strlen(PSBT_B64), raw, sizeof(raw));
    for (size_t cut = 0; cut < len; cut++) TEST_ASSERT_FALSE(psbtWellFormed(raw, cut));
    uint8_t bad[1024];
    memcpy(bad, raw, len);
    TEST_ASSERT_TRUE(bad[170] == 0x02 || bad[170] == 0x03);   // the input derivation's pubkey
    bad[170] = 0x05;                                          // ...made an invalid point encoding
    TEST_ASSERT_FALSE(psbtWellFormed(bad, len));
    const uint8_t rawTx[] = { 0x02, 0x00, 0x00, 0x00, 0x01 };   // a raw tx is not a PSBT
    TEST_ASSERT_FALSE(psbtWellFormed(rawTx, sizeof(rawTx)));
}

int main(int, char **) {
    UNITY_BEGIN();
    RUN_TEST(test_bip39_words);
    RUN_TEST(test_bip84_addresses_and_descriptor);
    RUN_TEST(test_bip44_btc_and_eth_addresses);
    RUN_TEST(test_eth_transaction_signature);
    RUN_TEST(test_erc20_and_chain);
    RUN_TEST(test_psbt_review_and_sign);
    RUN_TEST(test_psbt_malformed_refused);
    return UNITY_END();
}
