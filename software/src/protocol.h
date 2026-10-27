#ifndef SOTERIA_PROTOCOL_H
#define SOTERIA_PROTOCOL_H

#include <Arduino.h>
#include <ArduinoJson.h>
#include <Adafruit_SSD1306.h>
#include <SecureStorage.h>

#define SOTERIA_FW_VERSION    "0.4.0"
#define SOTERIA_PROTO_VERSION 1

/* ------------------------------------------------------------------ */
/* Host protocol over USB CDC serial (JSON Lines)                      */
/*                                                                     */
/* One UTF-8 JSON object per line, '\n' terminated, in both directions: */
/*   request  {"id": 7, "cmd": "sign_eth_tx", "tx": "02f8..."}           */
/*   response {"id": 7, "ok": true,  "result": {...}}                    */
/*            {"id": 7, "ok": false, "error": {"code": "...", "msg": ..}}*/
/*   event    {"event": "confirm_on_device", "id": 7, "cmd": "..."}      */
/* Binary data travels as lowercase hex (PSBTs as base64). Large       */
/* payloads are read in place from the line buffer and large results  */
/* are streamed: the 32 KB of RAM cannot hold several copies.          */
/* A line that does not start                                          */
/* with '{' is a text command for terminals ("INFO", "SIGN ETH <hash>"),  */
/* answered in JSON as well. The full command list is in                */
/* web-client/README.md and is returned by {"cmd":"help"}.              */
/* ------------------------------------------------------------------ */

#define PROTO_MAX_LINE 3072   // request line, JSON included
#define PROTO_MAX_RAW  2048   // decoded transaction / PSBT / message bytes
#define PROTO_MAX_OUT  3584   // signed tx / PSBT: input + up to 109 B of signature per input

class SoteriaProtocol {
public:
    void begin(Adafruit_SSD1306 &display, SecureStorage &eeprom);

    // Call from every UI loop. Reads available serial input and answers
    // complete requests; requests needing confirmation block until the
    // user has answered on the device.
    void poll();

    // True once after a command changed the stored wallet (erase,
    // rename): the caller must reload what it displays.
    bool walletChanged();

private:
    typedef void (SoteriaProtocol::*Handler)(JsonDocument &req, JsonDocument &resp);
    struct Command {
        const char *name;
        Handler     fn;
        bool        needsWallet;
        const char *help;
    };
    static const Command commands[];

    Adafruit_SSD1306 *_display = nullptr;
    SecureStorage    *_eeprom = nullptr;
    size_t _len = 0;            // bytes of the current line received so far
    bool   _overflow = false;   // current line exceeded PROTO_MAX_LINE
    bool   _changed = false;
    bool   _hostAccess = false; // user allowed this session to read keys
    const char *_cmd = "";      // command being executed (for events)
    const char *_payload = nullptr;   // tx / psbt / hex value, in s_line
    size_t _payloadLen = 0;
    const char *_bigKey = nullptr;    // result field streamed after the JSON
    const uint8_t *_bigData = nullptr;
    size_t _bigLen = 0;
    bool _bigBase64 = false;

    void handleLine();
    void writeResponse(JsonDocument &resp);
    void streamResult(const char *key, const uint8_t *data, size_t len, bool base64);
    bool parseTextCommand(JsonDocument &req);
    void sendEvent(JsonDocument &resp, const char *event);
    bool requireHostAccess(JsonDocument &resp);
    bool walletPresent();
    void failStatus(JsonDocument &resp, int status);

    void cmdHelp(JsonDocument &req, JsonDocument &resp);
    void cmdPing(JsonDocument &req, JsonDocument &resp);
    void cmdInfo(JsonDocument &req, JsonDocument &resp);
    void cmdAddresses(JsonDocument &req, JsonDocument &resp);
    void cmdPubkeys(JsonDocument &req, JsonDocument &resp);
    void cmdSetName(JsonDocument &req, JsonDocument &resp);
    void cmdErase(JsonDocument &req, JsonDocument &resp);
    void cmdSignBtc(JsonDocument &req, JsonDocument &resp);
    void cmdSignEthHash(JsonDocument &req, JsonDocument &resp);
    void cmdSignEthTx(JsonDocument &req, JsonDocument &resp);
    void cmdSignEthMessage(JsonDocument &req, JsonDocument &resp);
    void cmdXpubs(JsonDocument &req, JsonDocument &resp);
    void cmdShowAddress(JsonDocument &req, JsonDocument &resp);
    void cmdSignPsbt(JsonDocument &req, JsonDocument &resp);
};

extern SoteriaProtocol gProtocol;

#endif // SOTERIA_PROTOCOL_H
