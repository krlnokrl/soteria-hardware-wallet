// ATECC508A tests: the read-only I2C driver (src/se/atecc.cpp) against the
// fake chip in test/libs/HostStubs, and the invariants of the planned slot
// map (src/se/se_layout.h) that must hold before it is ever locked.
#include <unity.h>

#include <HostStubs.h>
#include "se/atecc.h"
#include "se/se_layout.h"

static Atecc se;

void setUp(void) { hostReset(); }
void tearDown(void) {}

/* ---------------- driver ---------------- */

// Reference packets from the datasheet: the wake token 04 11 | 33 43 and
// the Info command 07 30 00 00 00 | 03 5D.
static void test_crc16_reference_packets(void) {
    const uint8_t wake[] = { 0x04, 0x11 };
    TEST_ASSERT_EQUAL_HEX16(0x4333, Atecc::crc16(wake, sizeof(wake)));
    const uint8_t info[] = { 0x07, 0x30, 0x00, 0x00, 0x00 };
    TEST_ASSERT_EQUAL_HEX16(0x5D03, Atecc::crc16(info, sizeof(info)));
}

static void test_wake_and_info(void) {
    TEST_ASSERT_TRUE(se.wake());
    se.sleep();
    uint8_t rev[4];
    TEST_ASSERT_EQUAL_HEX8(ATECC_SUCCESS, se.info(rev));
    TEST_ASSERT_EQUAL_HEX8(ATECC_REV_508A, rev[2]);
}

// The driver wakes a chip that is already awake (pulse ignored) too.
static void test_wake_when_already_awake(void) {
    TEST_ASSERT_TRUE(se.wake());
    TEST_ASSERT_TRUE(se.wake());
}

static void test_read_config_and_decode(void) {
    uint8_t cfg[ATECC_CONFIG_SIZE];
    TEST_ASSERT_EQUAL_HEX8(ATECC_SUCCESS, se.readConfig(cfg));
    TEST_ASSERT_EQUAL_MEMORY(hostAteccConfig(), cfg, ATECC_CONFIG_SIZE);

    uint8_t sn[9];
    seSerial(cfg, sn);
    TEST_ASSERT_EQUAL_HEX8(0x01, sn[0]);
    TEST_ASSERT_EQUAL_HEX8(0x23, sn[1]);
    TEST_ASSERT_EQUAL_HEX8(0xEE, sn[8]);
    TEST_ASSERT_EQUAL_HEX8(0xC0, cfg[SE_CFG_I2C_ADDR]);
    TEST_ASSERT_FALSE(seConfigLocked(cfg));
    TEST_ASSERT_FALSE(seDataLocked(cfg));
    for (int s = 0; s < SE_SLOTS; s++) TEST_ASSERT_FALSE(seSlotLocked(cfg, s));
    TEST_ASSERT_EQUAL_HEX16(0x208F, seSlotConfig(cfg, 0));
    TEST_ASSERT_EQUAL_HEX16(0x0033, seKeyConfig(cfg, 0));

    hostAteccConfig()[SE_CFG_LOCK_CFG] = 0x00;
    hostAteccConfig()[SE_CFG_SLOT_LOCK] = 0xFE;   // slot 0 locked
    TEST_ASSERT_EQUAL_HEX8(ATECC_SUCCESS, se.readConfig(cfg));
    TEST_ASSERT_TRUE(seConfigLocked(cfg));
    TEST_ASSERT_TRUE(seSlotLocked(cfg, 0));
    TEST_ASSERT_FALSE(seSlotLocked(cfg, 1));
}

static void test_retries_after_corrupt_response(void) {
    hostAteccCorrupt(1);
    uint8_t rev[4];
    TEST_ASSERT_EQUAL_HEX8(ATECC_SUCCESS, se.info(rev));
    hostAteccCorrupt(2);
    uint8_t cfg[ATECC_CONFIG_SIZE];
    TEST_ASSERT_EQUAL_HEX8(ATECC_SUCCESS, se.readConfig(cfg));
    TEST_ASSERT_EQUAL_MEMORY(hostAteccConfig(), cfg, ATECC_CONFIG_SIZE);
}

static void test_gives_up_on_persistent_errors(void) {
    hostAteccCorrupt(1000);
    uint8_t rev[4];
    TEST_ASSERT_NOT_EQUAL(ATECC_SUCCESS, se.info(rev));
}

static void test_no_device(void) {
    hostAteccSetPresent(false);
    uint8_t rev[4];
    TEST_ASSERT_FALSE(se.wake());
    TEST_ASSERT_EQUAL_HEX8(ATECC_NO_DEVICE, se.info(rev));
}

static void test_waits_for_busy_chip_and_times_out(void) {
    uint8_t rev[4];
    hostAteccSetBusyPolls(4);
    TEST_ASSERT_EQUAL_HEX8(ATECC_SUCCESS, se.info(rev));
    hostAteccSetBusyPolls(1000);
    TEST_ASSERT_NOT_EQUAL(ATECC_SUCCESS, se.info(rev));
}

// Phase 1 must never change the chip: only Read (0x02) and Info (0x30).
static void test_only_read_only_commands_sent(void) {
    uint8_t rev[4], cfg[ATECC_CONFIG_SIZE];
    se.info(rev);
    se.readConfig(cfg);
    hostAteccCorrupt(3);
    se.readConfig(cfg);
    TEST_ASSERT_TRUE(hostAteccOpcodes().size() >= 5);
    for (uint8_t op : hostAteccOpcodes()) TEST_ASSERT_TRUE(op == 0x02 || op == 0x30);
}

/* ---------------- planned slot map ---------------- */

static bool isPrivateKey(int s) { return SE_PLAN[s].keyConfig & KC_PRIVATE; }
static int writeKey(int s) { return (SE_PLAN[s].slotConfig >> 8) & 0x0F; }
static int readKey(int s) { return SE_PLAN[s].slotConfig & 0x0F; }
static bool hidden(int s) {   // secret and never readable
    return (SE_PLAN[s].slotConfig & SC_IS_SECRET) && !(SE_PLAN[s].slotConfig & SC_ENCRYPT_READ);
}

// Encodings cross-checked with Microchip's default TLS config (slot 0:
// SlotConfig 0x2083, KeyConfig 0x0033 = ours plus Lockable).
// Coldcard's ATECC508A layout uses the same words for its secrets
// (0x438F hidden, PUK-style write key 3), seeds (0x43C3 = ours with
// ReadKey/WriteKey 3) and last-good counters (0x4300).
static void test_plan_known_encodings(void) {
    TEST_ASSERT_EQUAL_HEX16(0x2083, SE_PLAN[SE_SLOT_IDENTITY].slotConfig);
    TEST_ASSERT_EQUAL_HEX16(0x0013, SE_PLAN[SE_SLOT_IDENTITY].keyConfig);
    TEST_ASSERT_EQUAL_HEX16(0x438F, SE_PLAN[SE_SLOT_PIN].slotConfig);
    TEST_ASSERT_EQUAL_HEX16(0x005C, SE_PLAN[SE_SLOT_PIN].keyConfig);
    TEST_ASSERT_EQUAL_HEX16(0x001C, SE_PLAN[SE_SLOT_STRETCH].keyConfig);
    TEST_ASSERT_EQUAL_HEX16(0x42C2, SE_PLAN[SE_SLOT_SEED].slotConfig);
    TEST_ASSERT_EQUAL_HEX16(0x41C1, SE_PLAN[SE_SLOT_FIDO].slotConfig);
    TEST_ASSERT_EQUAL_HEX16(0x4300, SE_PLAN[SE_SLOT_FW_POLICY].slotConfig);
    TEST_ASSERT_EQUAL_HEX16(0x4200, SE_PLAN[SE_SLOT_PIN_COUNT].slotConfig);
}

// Only SlotConfig and KeyConfig change; serial, I2C address, OTP mode,
// ChipMode, counters and lock bytes stay as read from the chip.
static void test_build_config(void) {
    uint8_t want[ATECC_CONFIG_SIZE];
    const uint8_t *cur = hostAteccConfig();
    seBuildConfig(cur, want);
    for (int i = 0; i < ATECC_CONFIG_SIZE; i++) {
        bool slotWords = (i >= SE_CFG_SLOT_CFG && i < SE_CFG_SLOT_CFG + 32) || i >= SE_CFG_KEY_CFG;
        if (!slotWords) TEST_ASSERT_EQUAL_HEX8_MESSAGE(cur[i], want[i], "byte outside the slot words");
    }
    for (int s = 0; s < SE_SLOTS; s++) {
        TEST_ASSERT_EQUAL_HEX16(SE_PLAN[s].slotConfig, seSlotConfig(want, s));
        TEST_ASSERT_EQUAL_HEX16(SE_PLAN[s].keyConfig, seKeyConfig(want, s));
    }
    int total = 0;
    for (int s = 0; s < SE_SLOTS; s++) total += seSlotSize(s);
    TEST_ASSERT_EQUAL(1208, total);   // ATECC508A data zone
}

// Hidden secrets never use ReadKey 0 (CheckMac/Copy source); keys used
// for GenDig require a random nonce, W (MAC challenge mode) must not.
static void test_plan_auth_keys(void) {
    const int keys[] = { SE_SLOT_PAIRING, SE_SLOT_PIN, SE_SLOT_PUK };
    for (int s : keys) {
        TEST_ASSERT_EQUAL_MESSAGE(0xF, readKey(s), SE_PLAN[s].role);
        TEST_ASSERT_TRUE_MESSAGE(SE_PLAN[s].keyConfig & KC_REQ_RANDOM, SE_PLAN[s].role);
        TEST_ASSERT_FALSE_MESSAGE(SE_PLAN[s].slotConfig & SC_NO_MAC, SE_PLAN[s].role);
    }
    TEST_ASSERT_EQUAL(0xF, readKey(SE_SLOT_STRETCH));
    TEST_ASSERT_FALSE(SE_PLAN[SE_SLOT_STRETCH].keyConfig & KC_REQ_RANDOM);
    TEST_ASSERT_FALSE(SE_PLAN[SE_SLOT_STRETCH].slotConfig & SC_NO_MAC);
}

// Tinkerer rule: the lock freezes rules, never contents.
static void test_plan_nothing_permanent(void) {
    for (int s = 0; s < SE_SLOTS; s++) {
        TEST_ASSERT_FALSE_MESSAGE(SE_PLAN[s].keyConfig & KC_LOCKABLE, SE_PLAN[s].role);
        TEST_ASSERT_FALSE_MESSAGE(SE_PLAN[s].slotConfig & SC_LIMITED_USE, SE_PLAN[s].role);
        TEST_ASSERT_FALSE_MESSAGE(SE_PLAN[s].keyConfig & KC_REQ_AUTH, SE_PLAN[s].role);
        uint16_t writeCfg = SE_PLAN[s].slotConfig & 0xF000;
        if (isPrivateKey(s)) {
            TEST_ASSERT_EQUAL_HEX16_MESSAGE(SC_WRITE_GENKEY, writeCfg, SE_PLAN[s].role);
        } else {
            TEST_ASSERT_EQUAL_HEX16_MESSAGE(SC_WRITE_ENCRYPT, writeCfg, SE_PLAN[s].role);
        }
    }
}

// Every rewritable slot can be reached from the PUK: its WriteKey chain
// ends at the PUK slot, so knowing the PUK nothing ever gets stuck.
static void test_plan_puk_reaches_every_slot(void) {
    for (int s = 0; s < SE_SLOTS; s++) {
        if (isPrivateKey(s)) continue;   // GenKey, no write key
        int k = s;
        for (int hop = 0; hop < SE_SLOTS && k != SE_SLOT_PUK; hop++) k = writeKey(k);
        TEST_ASSERT_EQUAL_MESSAGE(SE_SLOT_PUK, k, SE_PLAN[s].role);
    }
    TEST_ASSERT_EQUAL(SE_SLOT_PUK, writeKey(SE_SLOT_PUK));
}

static void test_plan_secrets(void) {
    // Keys behind other slots are never readable, not even encrypted.
    const int keys[] = { SE_SLOT_PAIRING, SE_SLOT_PIN, SE_SLOT_PUK, SE_SLOT_STRETCH };
    for (int s : keys) TEST_ASSERT_TRUE_MESSAGE(hidden(s), SE_PLAN[s].role);
    // Private keys never leave the chip.
    for (int s = 0; s < SE_SLOTS; s++) {
        if (isPrivateKey(s)) TEST_ASSERT_TRUE_MESSAGE(SE_PLAN[s].slotConfig & SC_IS_SECRET, SE_PLAN[s].role);
    }
    // The seeds only come out with the PIN; FIDO2 works without it.
    TEST_ASSERT_TRUE(SE_PLAN[SE_SLOT_SEED].slotConfig & SC_ENCRYPT_READ);
    TEST_ASSERT_EQUAL(SE_SLOT_PIN, readKey(SE_SLOT_SEED));
    TEST_ASSERT_EQUAL(SE_SLOT_PIN, writeKey(SE_SLOT_SEED));
    TEST_ASSERT_EQUAL(SE_SLOT_PIN, readKey(SE_SLOT_SPARE_SEED));
    TEST_ASSERT_EQUAL(SE_SLOT_PAIRING, readKey(SE_SLOT_FIDO));
    // Firmware trust anchors can only be changed with the PUK.
    TEST_ASSERT_EQUAL(SE_SLOT_PUK, writeKey(SE_SLOT_FW_KEY));
    TEST_ASSERT_EQUAL(SE_SLOT_PUK, writeKey(SE_SLOT_FW_POLICY));
    TEST_ASSERT_EQUAL(SE_SLOT_PUK, writeKey(SE_SLOT_PIN));
}

int main(int, char **) {
    UNITY_BEGIN();
    RUN_TEST(test_crc16_reference_packets);
    RUN_TEST(test_wake_and_info);
    RUN_TEST(test_wake_when_already_awake);
    RUN_TEST(test_read_config_and_decode);
    RUN_TEST(test_retries_after_corrupt_response);
    RUN_TEST(test_gives_up_on_persistent_errors);
    RUN_TEST(test_no_device);
    RUN_TEST(test_waits_for_busy_chip_and_times_out);
    RUN_TEST(test_only_read_only_commands_sent);
    RUN_TEST(test_plan_known_encodings);
    RUN_TEST(test_build_config);
    RUN_TEST(test_plan_auth_keys);
    RUN_TEST(test_plan_nothing_permanent);
    RUN_TEST(test_plan_puk_reaches_every_slot);
    RUN_TEST(test_plan_secrets);
    return UNITY_END();
}
