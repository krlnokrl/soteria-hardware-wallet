// FIDO2 / U2F sanity tests: the real src/u2f.cpp driven over (emulated) USB
// HID like a browser does - register, sign in, verify both signatures,
// survive a reboot, honour the buttons.
#include <unity.h>

#include <new>
#include <vector>
#include <Hash.h>
#include <HostStubs.h>
#include <uECC.h>
#include "u2f.h"
#include "wallet.h"

typedef std::vector<uint8_t> Bytes;

static Adafruit_SSD1306 display;
static SecureStorage eeprom(0x50);
static uint32_t cid;

/* ---------------- CTAPHID framing ---------------- */

static void send(uint32_t channel, uint8_t cmd, const Bytes &data) {
    uint8_t pkt[64] = { 0 };
    pkt[0] = channel >> 24; pkt[1] = channel >> 16; pkt[2] = channel >> 8; pkt[3] = channel;
    pkt[4] = cmd;
    pkt[5] = data.size() >> 8; pkt[6] = data.size() & 0xFF;
    size_t off = data.size() < 57 ? data.size() : 57;
    memcpy(pkt + 7, data.data(), off);
    hostUsbOut(pkt);
    for (uint8_t seq = 0; off < data.size(); seq++) {
        memset(pkt + 4, 0, 60);
        pkt[4] = seq;
        size_t n = data.size() - off < 59 ? data.size() - off : 59;
        memcpy(pkt + 5, data.data() + off, n);
        hostUsbOut(pkt);
        off += n;
    }
}

// Run the device until it answers (keepalives skipped); returns the payload.
static Bytes receive(uint8_t *cmdOut = nullptr) {
    uint8_t pkt[64];
    for (int i = 0; i < 1000; i++) {
        gU2F.poll();
        while (hostUsbIn(pkt)) {
            if (pkt[4] == 0xBB) continue;                        // keepalive
            size_t len = pkt[5] << 8 | pkt[6];
            Bytes out(pkt + 7, pkt + 7 + (len < 57 ? len : 57));
            while (out.size() < len && hostUsbIn(pkt)) {
                size_t n = len - out.size() < 59 ? len - out.size() : 59;
                out.insert(out.end(), pkt + 5, pkt + 5 + n);
            }
            if (cmdOut) *cmdOut = pkt[4];
            return out;
        }
    }
    TEST_FAIL_MESSAGE("no answer from the authenticator");
    return Bytes();
}

static Bytes ctap2(const Bytes &request) {
    send(cid, 0x90, request);
    return receive();
}

/* ---------------- minimal CBOR writer ---------------- */

struct Cbor {
    Bytes b;
    Cbor &head(uint8_t major, uint64_t v) {
        if (v < 24) b.push_back(major << 5 | v);
        else if (v < 256) { b.push_back(major << 5 | 24); b.push_back(v); }
        else { b.push_back(major << 5 | 25); b.push_back(v >> 8); b.push_back(v & 0xFF); }
        return *this;
    }
    Cbor &uint(uint64_t v) { return head(0, v); }
    Cbor &neg(int64_t v) { return head(1, (uint64_t)(-1 - v)); }
    Cbor &bytes(const uint8_t *d, size_t n) { head(2, n); b.insert(b.end(), d, d + n); return *this; }
    Cbor &text(const char *s) { head(3, strlen(s)); b.insert(b.end(), s, s + strlen(s)); return *this; }
    Cbor &array(size_t n) { return head(4, n); }
    Cbor &map(size_t n) { return head(5, n); }
};

static const uint8_t CDH[32] = { 1, 2, 3, 4, 5, 6, 7, 8 };   // client data hash (any 32 bytes)

static Bytes makeCredential(const char *rpId) {
    Cbor c;
    c.b.push_back(0x01);
    c.map(4);
    c.uint(1).bytes(CDH, 32);
    c.uint(2).map(2).text("id").text(rpId).text("name").text("Example");
    const uint8_t user[3] = { 9, 9, 9 };
    c.uint(3).map(2).text("id").bytes(user, 3).text("name").text("alice");
    c.uint(4).array(1).map(2).text("alg").neg(-7).text("type").text("public-key");
    return ctap2(c.b);
}

static Bytes getAssertion(const char *rpId, const uint8_t credId[32]) {
    Cbor c;
    c.b.push_back(0x02);
    c.map(3);
    c.uint(1).text(rpId);
    c.uint(2).bytes(CDH, 32);
    c.uint(3).array(1).map(2).text("id").bytes(credId, 32).text("type").text("public-key");
    return ctap2(c.b);
}

/* ---------------- helpers ---------------- */

// DER ECDSA signature -> 64-byte r | s for micro-ecc.
static void derToRaw(const uint8_t *der, uint8_t raw[64]) {
    const uint8_t *p = der + 2;
    for (int part = 0; part < 2; part++) {
        uint8_t len = p[1];
        const uint8_t *v = p + 2;
        while (len > 32) { v++; len--; }               // drop sign padding
        memset(raw + 32 * part, 0, 32 - len);
        memcpy(raw + 32 * part + 32 - len, v, len);
        p += 2 + p[1];
    }
}

static bool verifyP256(const uint8_t pub[64], const Bytes &signedData, const uint8_t *der) {
    uint8_t hash[32], sig[64];
    sha256(signedData.data(), signedData.size(), hash);
    derToRaw(der, sig);
    return uECC_verify(pub, hash, 32, sig, uECC_secp256r1()) == 1;
}

static void pressYes() { hostPress(YES, 3, 40); }   // ~200 ms: longer than the debounce

static void boot() {
    gU2F.~SoteriaU2F();              // power cycle: RAM state gone, EEPROM kept
    new (&gU2F) SoteriaU2F();
    gU2F.begin(display);
    const uint8_t nonce[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    send(0xFFFFFFFF, 0x86, Bytes(nonce, nonce + 8));   // CTAPHID_INIT on the broadcast channel
    Bytes r = receive();
    TEST_ASSERT_EQUAL_MEMORY(nonce, r.data(), 8);
    cid = (uint32_t)r[8] << 24 | r[9] << 16 | r[10] << 8 | r[11];
}

void setUp(void) {
    hostReset();
    uint8_t secret[32];              // the FIDO2 master secret a generated wallet stores
    memset(secret, 0x42, sizeof(secret));
    hostSetFidoSecret(secret);
    boot();
}
void tearDown(void) {}

/* ---------------- tests ---------------- */

static void test_get_info(void) {
    Bytes r = ctap2(Bytes(1, 0x04));
    TEST_ASSERT_EQUAL_HEX8(0x00, r[0]);
    TEST_ASSERT_TRUE(r.size() > 20);
}

// Register, then sign in twice (once after a reboot): both signatures
// verify against the credential's public key, the counter only goes up.
static void test_register_and_sign_in(void) {
    pressYes();
    Bytes mc = makeCredential("example.com");
    TEST_ASSERT_EQUAL_HEX8(0x00, mc[0]);
    // {1: "packed", 2: authData(164), 3: {"alg": -7, "sig": DER}}
    TEST_ASSERT_EQUAL_HEX8(0x58, mc[11]);
    TEST_ASSERT_EQUAL_UINT8(164, mc[12]);
    const uint8_t *ad = &mc[13];
    uint8_t rpIdHash[32];
    sha256((const uint8_t *)"example.com", 11, rpIdHash);
    TEST_ASSERT_EQUAL_MEMORY(rpIdHash, ad, 32);
    TEST_ASSERT_EQUAL_HEX8(0x41, ad[32]);                    // user present + attested data
    uint8_t credId[32], pub[64];
    memcpy(credId, ad + 55, 32);
    memcpy(pub, ad + 97, 32);                                // COSE x
    memcpy(pub + 32, ad + 132, 32);                          // COSE y
    Bytes signedData(ad, ad + 164);
    signedData.insert(signedData.end(), CDH, CDH + 32);
    TEST_ASSERT_TRUE_MESSAGE(verifyP256(pub, signedData, &mc[190]), "attestation signature");

    uint32_t lastCount = 0;
    for (int round = 0; round < 2; round++) {
        if (round == 1) boot();                              // credentials are not stored in RAM
        pressYes();
        Bytes ga = getAssertion("example.com", credId);
        TEST_ASSERT_EQUAL_HEX8(0x00, ga[0]);
        TEST_ASSERT_EQUAL_MEMORY(credId, &ga[9], 32);
        const uint8_t *aad = &ga[60];
        TEST_ASSERT_EQUAL_HEX8(0x01, aad[32] & 0x01);          // user present
        uint32_t count = (uint32_t)aad[33] << 24 | aad[34] << 16 | aad[35] << 8 | aad[36];
        TEST_ASSERT_TRUE(count > lastCount);
        lastCount = count;
        Bytes sd(aad, aad + 37);
        sd.insert(sd.end(), CDH, CDH + 32);
        TEST_ASSERT_TRUE_MESSAGE(verifyP256(pub, sd, &ga[100]), "assertion signature");
    }
}

// NO button denies; a credential only works for the site it was made for.
static void test_deny_and_wrong_site(void) {
    pressYes();
    Bytes mc = makeCredential("example.com");
    TEST_ASSERT_EQUAL_HEX8(0x00, mc[0]);
    uint8_t credId[32];
    memcpy(credId, &mc[13 + 55], 32);

    hostPress(NO, 3, 40);
    TEST_ASSERT_EQUAL_HEX8(0x27, getAssertion("example.com", credId)[0]);   // OPERATION_DENIED
    TEST_ASSERT_EQUAL_HEX8(0x2E, getAssertion("evil.example", credId)[0]);  // NO_CREDENTIALS
}

// Without a wallet (no FIDO master secret) nothing can be registered.
static void test_no_wallet_refuses(void) {
    hostReset();
    boot();
    TEST_ASSERT_EQUAL_HEX8(0x27, makeCredential("example.com")[0]);         // OPERATION_DENIED
}

int main(int, char **) {
    UNITY_BEGIN();
    RUN_TEST(test_get_info);
    RUN_TEST(test_register_and_sign_in);
    RUN_TEST(test_deny_and_wrong_site);
    RUN_TEST(test_no_wallet_refuses);
    return UNITY_END();
}
