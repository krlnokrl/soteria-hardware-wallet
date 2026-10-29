// Wallet secrets in the secure element (src/se/se_wallet.cpp) against the
// fake ATECC508A in test/libs/HostStubs, provisioned as env:seprov leaves
// the real chip: create, unlock, wrong PIN count, PIN change, wipe,
// factory reset, FIDO2 secret and counter, randomness.
#include <unity.h>

#include <HostStubs.h>
#include "se/atecc.h"
#include "se/se_layout.h"
#include "se/se_wallet.h"

static SecureStorage eeprom(0x50);
static Atecc chip;
static SeWallet se;

static const uint8_t PAIRING[32] = { 0x50, 0x41, 0x49, 0x52 };
static const uint8_t STRETCH[32] = { 0x57 };
static const uint8_t PIN[SE_PIN_DIGITS]   = { 1, 2, 3, 4, 5, 6 };
static const uint8_t PIN2[SE_PIN_DIGITS]  = { 0xA, 0xB, 0xC, 0xD, 0xE, 0xF };
static const uint8_t WRONG[SE_PIN_DIGITS] = { 1, 2, 3, 4, 5, 7 };
static uint8_t ROOT[SE_ROOT_SIZE], FIDO[32];

static void pairEeprom() {
    uint8_t cfg[ATECC_CONFIG_SIZE];
    TEST_ASSERT_EQUAL_HEX8(ATECC_SUCCESS, chip.readConfig(cfg));
    SeRecord rec;
    memset(&rec, 0, sizeof(rec));
    rec.magic = SE_RECORD_MAGIC;
    seSerial(cfg, rec.serial);
    memcpy(rec.pairing, PAIRING, 32);
    eeprom.writeSe(rec);
}

void setUp(void) {
    hostReset();
    hostAteccProvision(PAIRING, STRETCH);
    pairEeprom();
    for (int i = 0; i < SE_ROOT_SIZE; i++) ROOT[i] = (uint8_t)(i * 3 + 1);
    for (int i = 0; i < 32; i++) FIDO[i] = (uint8_t)(0xF0 ^ i);
    TEST_ASSERT_TRUE(se.begin(chip, eeprom));
}
void tearDown(void) {}

static void create(uint8_t puk[SE_PUK_DIGITS]) {
    TEST_ASSERT_EQUAL(SE_OK, se.create(PIN, ROOT, FIDO, nullptr, puk));
}

/* ---------------- tests ---------------- */

static void test_not_ready_unprovisioned_or_unpaired(void) {
    hostReset();                                     // unlocked factory chip
    pairEeprom();
    TEST_ASSERT_FALSE(se.begin(chip, eeprom));
    uint8_t puk[SE_PUK_DIGITS];
    TEST_ASSERT_EQUAL(SE_NOT_READY, se.create(PIN, ROOT, FIDO, nullptr, puk));

    hostAteccProvision(PAIRING, STRETCH);            // locked, but EEPROM erased
    SeRecord blank;
    memset(&blank, 0xFF, sizeof(blank));
    eeprom.writeSe(blank);
    TEST_ASSERT_FALSE(se.begin(chip, eeprom));
}

static void test_create_and_unlock(void) {
    uint8_t puk[SE_PUK_DIGITS], root[SE_ROOT_SIZE];
    create(puk);
    for (int i = 0; i < SE_PUK_DIGITS; i++) TEST_ASSERT_TRUE(puk[i] < 16);
    uint32_t failed = 99;
    TEST_ASSERT_EQUAL(SE_OK, se.unlock(PIN, root, &failed));
    TEST_ASSERT_EQUAL_MEMORY(ROOT, root, SE_ROOT_SIZE);
    TEST_ASSERT_EQUAL_UINT32(0, failed);
}

// The chip refuses a wrong PIN; the next good unlock reports the attempts.
static void test_wrong_pin_counted(void) {
    uint8_t puk[SE_PUK_DIGITS], root[SE_ROOT_SIZE];
    create(puk);
    TEST_ASSERT_EQUAL(SE_WRONG_PIN, se.unlock(WRONG, root, nullptr));
    TEST_ASSERT_EACH_EQUAL_HEX8(0, root, SE_ROOT_SIZE);
    TEST_ASSERT_EQUAL(SE_WRONG_PIN, se.unlock(WRONG, root, nullptr));
    uint32_t failed = 0;
    TEST_ASSERT_EQUAL(SE_OK, se.unlock(PIN, root, &failed));
    TEST_ASSERT_EQUAL_UINT32(2, failed);
    TEST_ASSERT_EQUAL(SE_OK, se.unlock(PIN, root, &failed));
    TEST_ASSERT_EQUAL_UINT32(0, failed);
}

// Secrets never readable in the clear, not even by the stub's own reads.
static void test_seed_not_readable_without_pin(void) {
    uint8_t puk[SE_PUK_DIGITS], out[32];
    create(puk);
    TEST_ASSERT_NOT_EQUAL(ATECC_SUCCESS, chip.read32(SE_SLOT_SEED, 0, out));
    TEST_ASSERT_NOT_EQUAL(ATECC_SUCCESS, chip.readEncrypted(SE_SLOT_SEED, 0, SE_SLOT_PAIRING, PAIRING, out));
}

static void test_fido_secret_and_counter(void) {
    uint8_t puk[SE_PUK_DIGITS], secret[32];
    TEST_ASSERT_FALSE(se.fidoSecret(secret));        // no wallet yet
    create(puk);
    TEST_ASSERT_TRUE(se.fidoSecret(secret));
    TEST_ASSERT_EQUAL_MEMORY(FIDO, secret, 32);
    uint32_t a, b, c;
    TEST_ASSERT_TRUE(se.fidoCounter(a, false));
    TEST_ASSERT_TRUE(se.fidoCounter(b, true));
    TEST_ASSERT_TRUE(se.fidoCounter(c, false));
    TEST_ASSERT_EQUAL_UINT32(a + 1, b);
    TEST_ASSERT_EQUAL_UINT32(b, c);
}

// After the first wallet the chip holds a PUK: a new wallet needs it, and
// gets a new one.
static void test_new_wallet_needs_puk(void) {
    uint8_t puk[SE_PUK_DIGITS], puk2[SE_PUK_DIGITS], wrongPuk[SE_PUK_DIGITS], root[SE_ROOT_SIZE];
    create(puk);
    TEST_ASSERT_EQUAL(SE_NEED_PUK, se.create(PIN2, ROOT, FIDO, nullptr, puk2));
    memcpy(wrongPuk, puk, sizeof(puk));
    wrongPuk[0] ^= 1;
    TEST_ASSERT_EQUAL(SE_WRONG_PUK, se.create(PIN2, ROOT, FIDO, wrongPuk, puk2));
    TEST_ASSERT_EQUAL(SE_OK, se.unlock(PIN, root, nullptr));          // nothing changed
    TEST_ASSERT_EQUAL(SE_OK, se.create(PIN2, ROOT, FIDO, puk, puk2));
    TEST_ASSERT_EQUAL(SE_OK, se.unlock(PIN2, root, nullptr));
    TEST_ASSERT_EQUAL(SE_WRONG_PUK, se.create(PIN, ROOT, FIDO, puk, wrongPuk));   // old PUK gone
}

static void test_change_pin(void) {
    uint8_t puk[SE_PUK_DIGITS], wrongPuk[SE_PUK_DIGITS], root[SE_ROOT_SIZE];
    create(puk);
    memcpy(wrongPuk, puk, sizeof(puk));
    wrongPuk[7] ^= 0x8;
    TEST_ASSERT_EQUAL(SE_WRONG_PIN, se.changePin(WRONG, puk, PIN2));
    TEST_ASSERT_EQUAL(SE_WRONG_PUK, se.changePin(PIN, wrongPuk, PIN2));
    TEST_ASSERT_EQUAL(SE_OK, se.unlock(PIN, root, nullptr));          // still the old PIN
    TEST_ASSERT_EQUAL(SE_OK, se.changePin(PIN, puk, PIN2));
    TEST_ASSERT_EQUAL(SE_WRONG_PIN, se.unlock(PIN, root, nullptr));
    TEST_ASSERT_EQUAL(SE_OK, se.unlock(PIN2, root, nullptr));
    TEST_ASSERT_EQUAL_MEMORY(ROOT, root, SE_ROOT_SIZE);
}

static void test_wipe_with_pin(void) {
    uint8_t puk[SE_PUK_DIGITS], puk2[SE_PUK_DIGITS], secret[32], root[SE_ROOT_SIZE];
    create(puk);
    TEST_ASSERT_EQUAL(SE_WRONG_PIN, se.wipe(WRONG));
    TEST_ASSERT_TRUE(se.fidoSecret(secret));
    TEST_ASSERT_EQUAL(SE_OK, se.wipe(PIN));
    TEST_ASSERT_FALSE(se.fidoSecret(secret));
    TEST_ASSERT_EQUAL(SE_OK, se.unlock(PIN, root, nullptr));          // PIN stays...
    TEST_ASSERT_FALSE(memcmp(ROOT, root, SE_ROOT_SIZE) == 0);         // ...the seed is gone
    TEST_ASSERT_EQUAL(SE_NEED_PUK, se.create(PIN, ROOT, FIDO, nullptr, puk2));
    TEST_ASSERT_EQUAL(SE_OK, se.create(PIN, ROOT, FIDO, puk, puk2));
}

static void test_factory_reset_with_puk(void) {
    uint8_t puk[SE_PUK_DIGITS], puk2[SE_PUK_DIGITS], wrongPuk[SE_PUK_DIGITS], secret[32], root[SE_ROOT_SIZE];
    create(puk);
    memset(wrongPuk, 0, sizeof(wrongPuk));
    TEST_ASSERT_EQUAL(SE_WRONG_PUK, se.factoryReset(wrongPuk));
    TEST_ASSERT_EQUAL(SE_OK, se.unlock(PIN, root, nullptr));
    TEST_ASSERT_EQUAL(SE_OK, se.factoryReset(puk));
    TEST_ASSERT_FALSE(se.fidoSecret(secret));
    TEST_ASSERT_EQUAL(SE_WRONG_PIN, se.unlock(PIN, root, nullptr));
    TEST_ASSERT_EQUAL(SE_OK, se.create(PIN2, ROOT, FIDO, nullptr, puk2));   // factory state again
    TEST_ASSERT_EQUAL(SE_OK, se.unlock(PIN2, root, nullptr));
    TEST_ASSERT_EQUAL_MEMORY(ROOT, root, SE_ROOT_SIZE);
}

static void test_random(void) {
    uint8_t a[40], b[40];
    TEST_ASSERT_TRUE(se.random(a, sizeof(a)));
    TEST_ASSERT_TRUE(se.random(b, sizeof(b)));
    TEST_ASSERT_FALSE(memcmp(a, b, sizeof(a)) == 0);
}

int main(int, char **) {
    UNITY_BEGIN();
    RUN_TEST(test_not_ready_unprovisioned_or_unpaired);
    RUN_TEST(test_create_and_unlock);
    RUN_TEST(test_wrong_pin_counted);
    RUN_TEST(test_seed_not_readable_without_pin);
    RUN_TEST(test_fido_secret_and_counter);
    RUN_TEST(test_new_wallet_needs_puk);
    RUN_TEST(test_change_pin);
    RUN_TEST(test_wipe_with_pin);
    RUN_TEST(test_factory_reset_with_puk);
    RUN_TEST(test_random);
    return UNITY_END();
}
