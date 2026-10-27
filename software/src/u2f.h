#ifndef SOTERIA_U2F_H
#define SOTERIA_U2F_H

#include <Arduino.h>
#include <uECC.h>
#include <Key.h>
#include <Adafruit_SSD1306.h>
#include <SecureStorage.h>

// The PluggableUSB API (needed for the USB HID/CTAPHID interface) is only
// present on the Adafruit SAMD fork, not on vanilla arduino-samd. Gate on a
// build flag so both environments compile.
#ifdef SOTERIA_HAS_PLUGGABLE_USB
#   include <USB/PluggableUSB.h>
#endif

/* ------------------------------------------------------------------ */
/* CTAPHID constants                                                  */
/* ------------------------------------------------------------------ */

#define HID_CLASS          0x03
#define HID_SUBCLASS       0x00
#define HID_PROTOCOL       0x00

// CTAPHID commands as they appear on the wire (raw value | TYPE_INIT).
#define CTAPHID_TYPE_INIT      0x80
#define CTAPHID_CMD_PING       0x81
#define CTAPHID_CMD_MSG        0x83
#define CTAPHID_CMD_INIT       0x86
#define CTAPHID_CMD_WINK       0x88
#define CTAPHID_CMD_CBOR       0x90
#define CTAPHID_CMD_CANCEL     0x91
#define CTAPHID_CMD_KEEPALIVE  0xBB
#define CTAPHID_CMD_ERROR      0xBF

// The unallocated "no channel" address used before INIT assigns one.
#define CTAPHID_CID_BROADCAST  0xFFFFFFFFUL

// Payload of a CTAPHID_CMD_ERROR packet.
#define CTAPHID_ERR_INVALID_CMD 0x01
#define CTAPHID_ERR_INVALID_LEN 0x02
#define CTAPHID_ERR_INVALID_SEQ 0x03
#define CTAPHID_ERR_MSG_TIMEOUT 0x05
#define CTAPHID_ERR_CHANNEL_BUSY 0x06
#define CTAPHID_ERR_INVALID_CID 0x07
#define CTAPHID_ERR_OTHER       0x08

// Capability bits of the CTAPHID_INIT response.
#define CTAPHID_CAP_CBOR        0x04   // CTAP2 (CBOR commands) supported
#define CTAPHID_CAP_NMSG        0x08   // CTAPHID_MSG (CTAP1/U2F) not supported

// CTAP2 command bytes (first byte of a CTAPHID_CBOR payload).
#define CTAP2_CMD_MAKE_CREDENTIAL 0x01
#define CTAP2_CMD_GET_ASSERTION   0x02
#define CTAP2_CMD_GET_INFO        0x04

/* ------------------------------------------------------------------ */
/* Credentials                                                         */
/*                                                                     */
/* Non-resident and stateless: nothing per-site is stored. The         */
/* credential id the RP keeps is nonce(16) | tag(16) and both the       */
/* P-256 key and the tag are HMACs of the FIDO master secret (EEPROM    */
/* key slot FIDO_KEY_SLOT) over rpIdHash | nonce, so credentials        */
/* survive power cycles and there is no slot limit.                     */
/* ------------------------------------------------------------------ */

#define FIDO_CRED_NONCE_LEN 16
#define FIDO_CRED_TAG_LEN   16
#define FIDO_CRED_ID_LEN    (FIDO_CRED_NONCE_LEN + FIDO_CRED_TAG_LEN)

/* ------------------------------------------------------------------ */
/* USB HID + CTAPHID + U2F device                                     */
/* ------------------------------------------------------------------ */

class SoteriaU2F {
public:
    SoteriaU2F();

    // Call once from setup(). Registers the HID interface when the core
    // supports PluggableUSB; otherwise a no-op. The display and buttons
    // are used for the user-presence prompt, the EEPROM for the master
    // secret and signature counter.
    bool begin(Adafruit_SSD1306 &display, SecureStorage &eeprom);

    // Call repeatedly from loop(). Services incoming HID reports.
    void poll();

#ifdef SOTERIA_HAS_PLUGGABLE_USB
private:
    // --- USB HID module (PluggableUSB) -----------------------------
    class HIDModule : public PluggableUSBModule {
    public:
        HIDModule();
        int getInterface(uint8_t* interfaceCount) override;
        int getDescriptor(USBSetup& setup) override;
        bool setup(USBSetup& setup) override;

        // Endpoint number assigned by PluggableUSB at plug() time.
        uint8_t endpointNumber() const { return pluggedEndpoint; }

        friend class SoteriaU2F;
    };

    HIDModule _hid;
    uint8_t   _epIn;   // interrupt IN  endpoint number
    uint8_t   _epOut;  // interrupt OUT endpoint number

    bool sendReport(const uint8_t* data, uint8_t len);
    int  recvReport(uint8_t* buf, uint8_t maxLen);

    // --- CTAPHID receive / reassembly state ------------------------
    uint8_t  _rxPkt[64];        // raw report from the interrupt OUT endpoint
    uint8_t  _rxFrame[1024];    // reassembled CTAPHID message payload
    uint16_t _rxGot;            // payload bytes received so far
    uint16_t _rxExpected;       // bcnt of the message being reassembled
    uint8_t  _rxSeq;            // next continuation sequence number expected
    uint8_t  _rxCmd;            // command of the message being reassembled
    uint32_t _rxCid;            // channel of the message being reassembled
    uint32_t _rxLast;           // millis() of its latest packet (timeout)
    bool     _rxActive;         // a message is currently being reassembled
    uint32_t _nextCid;          // last channel id handed out by INIT
    uint8_t  _txBuf[512];       // staging buffer for CTAP2 responses

    // --- CTAPHID transport -----------------------------------------
    void ctaphidPacket(const uint8_t* pkt, uint8_t len);
    void ctaphidMessageDone();
    void ctaphidSend(uint32_t cid, uint8_t cmd, const uint8_t* data, uint16_t len);
    void ctaphidSendError(uint32_t cid, uint8_t err);
    void ctaphidSendKeepalive(uint32_t cid, uint8_t status);
    void ctaphidInit(uint32_t cid, const uint8_t* nonce);
    void ctaphidDispatch(uint8_t cmd, const uint8_t* data, uint16_t len);

    // --- CTAP2 ------------------------------------------------------
    void ctap2Dispatch(const uint8_t* req, uint16_t reqLen);
    void ctap2GetInfo();
    void ctap2MakeCredential(const uint8_t* req, uint16_t reqLen);
    void ctap2GetAssertion(const uint8_t* req, uint16_t reqLen);
    void ctap2SendStatus(uint8_t code);
    uint8_t  waitForUserPresence(const char* action, const uint8_t* rpId, uint16_t rpIdLen);
    uint32_t nextSignCount();
#endif

    Adafruit_SSD1306* _display;
    SecureStorage*    _eeprom;
};

extern SoteriaU2F gU2F;

#endif // SOTERIA_U2F_H
