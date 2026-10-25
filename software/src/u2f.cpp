#include "u2f.h"

#include <uECC.h>
#include "utils.h"
#include "wallet.h"

#ifdef SOTERIA_HAS_PLUGGABLE_USB
#include <USB/USBAPI.h>
#include <USB/SAMD21_USBDevice.h>

// Defined in the core's USBCore.cpp (non-static) but not exported via headers.
extern USBDevice_SAMD21G18x usbd;

// Endpoint type descriptors handed to PluggableUSB. The actual endpoint
// numbers are assigned dynamically by plug() and stored in _epIn/_epOut.
static uint32_t g_hidEpType[2];

/**
 * Receive handler for the interrupt OUT endpoint (CTAPHID host->device).
 *
 * The core's initEP() for INTERRUPT|OUT only calls epHandlers[ep]->init()
 * and does no bank setup itself, so this handler must configure bank0
 * (address, size, type=4/INTERRUPT, arming) when init() runs at
 * SET_CONFIGURATION. Mirrors DoubleBufferedEPOutHandler but with a single
 * packet buffer: the bank is held "full" (BK0RDY=1 -> NAK) until poll()
 * consumes the packet, so back-to-back CTAPHID packets cannot overwrite
 * unread data.
 */
class InterruptOutHandler : public EPHandler {
public:
    // No user ctor: constant-initialized at load time (before gU2F), so it
    // is safe for HIDModule's constructor to reference it during the static
    // initialization phase.
    void attach(uint8_t epNum) { _ep = epNum; }

    void init() override {
        usbd.epBank0SetAddress(_ep, _buf);       // own buffer (core's is static)
        usbd.epBank0SetSize(_ep, 64);
        usbd.epBank0SetType(_ep, 4);   // 4 = INTERRUPT (SAMD PTYPE encoding)
        // Arm the bank: enable TC interrupt, clear byte count, BK0RDY=0 so
        // the endpoint ACKs the host's first OUT packet.
        usbd.epBank0EnableTransferComplete(_ep);
        usbd.epBank0SetMultiPacketSize(_ep, 64);
        usbd.epBank0SetByteCount(_ep, 0);
        usbd.epBank0ResetReady(_ep);
    }

    void handleEndpoint() override {
        // Called from the USB ISR when a packet lands in bank0.
        _count = usbd.epBank0ByteCount(_ep);
        // Ack TC so the level-triggered ISR does not re-enter, but do NOT
        // reset BK0RDY: the bank stays full (host NAKs) until recv().
        usbd.epBank0AckTransferComplete(_ep);
    }

    uint32_t recv(void* data, uint32_t len) override {
        uint32_t n = _count;
        if (n == 0) return 0;
        if (n > len) n = len;
        memcpy(data, _buf, n);
        _count = 0;
        // Re-arm the bank for the next packet (release()-equivalent).
        usbd.epBank0SetMultiPacketSize(_ep, 64);
        usbd.epBank0SetByteCount(_ep, 0);
        usbd.epBank0ResetReady(_ep);
        return n;
    }

    uint32_t available() const override { return _count; }

private:
    uint8_t _ep = 0;
    volatile uint32_t _count = 0;
    alignas(4) uint8_t _buf[64];   // USB writes packets here directly
};

// Declared before gU2F so it is initialized first (same TU, declaration order).
static InterruptOutHandler g_hidOutHandler;

SoteriaU2F::HIDModule::HIDModule()
    : PluggableUSBModule(2, 1, g_hidEpType) {
    g_hidEpType[0] = USB_ENDPOINT_TYPE_INTERRUPT | USB_ENDPOINT_IN(0);
    g_hidEpType[1] = USB_ENDPOINT_TYPE_INTERRUPT | USB_ENDPOINT_OUT(0);
    // Register before main(); initEndpoints() runs later, at the host's
    // SET_CONFIGURATION, and will call epHandlers[OUT]->init().
    PluggableUSB().plug(this);
    g_hidOutHandler.attach(pluggedEndpoint + 1);   // OUT = IN + 1
    USBDevice.setHandler(pluggedEndpoint + 1, &g_hidOutHandler);
}

int SoteriaU2F::HIDModule::getInterface(uint8_t* interfaceCount) {
    // Build the HID interface descriptor block dynamically using the
    // endpoint numbers assigned by PluggableUSB at plug() time.
    uint8_t epIn  = 0x80 | pluggedEndpoint;     // interrupt IN
    uint8_t epOut = 0x00 | (pluggedEndpoint + 1); // interrupt OUT

    static const uint8_t reportDesc[] = {
        0x06, 0xD0, 0xF1,        // Usage Page (FIDO)
        0x09, 0x01,              // Usage (CTAPHID)
        0xA1, 0x01,              // Collection (Application)
        0x09, 0x20,              //   Usage (Input Data)
        0x15, 0x00,              //   Logical Minimum (0)
        0x26, 0xFF, 0x00,        //   Logical Maximum (255)
        0x75, 0x08,              //   Report Size (8)
        0x95, 0x40,              //   Report Count (64)
        0x81, 0x02,              //   Input (Data, Variable, Absolute)
        0x09, 0x21,              //   Usage (Output Data)
        0x15, 0x00,              //   Logical Minimum (0)
        0x26, 0xFF, 0x00,        //   Logical Maximum (255)
        0x75, 0x08,              //   Report Size (8)
        0x95, 0x40,              //   Report Count (64)
        0x91, 0x02,              //   Output (Data, Variable, Absolute)
        0xC0                     // End Collection
    };
    const uint8_t reportDescLen = sizeof(reportDesc);

    uint8_t ifaceDesc[] = {
        9, 4, (uint8_t)pluggedInterface, 0, 2, HID_CLASS, HID_SUBCLASS, HID_PROTOCOL, 0
    };
    uint8_t hidDesc[] = {
        9, 0x21, 0x00, 0x01, 0, 1, 0x22,
        (uint8_t)(reportDescLen & 0xFF), (uint8_t)(reportDescLen >> 8)
    };
    // Endpoint descriptor layout: bLength, bDescriptorType, bEndpointAddress,
    // bmAttributes, wMaxPacketSize (lo, hi), bInterval. So "64, 0" is
    // wMaxPacketSize = 64 (full-speed interrupt max) and the last byte is
    // bInterval = 1 ms. Swapping those last two bytes makes Windows see
    // wMaxPacketSize = 0x0140 = 320 and bInterval = 0 -> the config
    // descriptor fails validation -> "Unknown USB Device (Invalid
    // Configuration Descriptor)".
    uint8_t epInDesc[]  = { 7, 5, epIn,  USB_ENDPOINT_TYPE_INTERRUPT, 64, 0, 1 };
    uint8_t epOutDesc[] = { 7, 5, epOut, USB_ENDPOINT_TYPE_INTERRUPT, 64, 0, 1 };

    uint8_t block[9 + 9 + 7 + 7];
    uint8_t* p = block;
    memcpy(p, ifaceDesc, 9); p += 9;
    memcpy(p, hidDesc, 9);   p += 9;
    memcpy(p, epInDesc, 7);  p += 7;
    memcpy(p, epOutDesc, 7); p += 7;

    *interfaceCount += 1;
    // Return the number of descriptor bytes sent: sendConfiguration() sums
    // these return values into the configuration descriptor's wTotalLength
    // (dry-run pass). Returning anything else (e.g. 1) makes Windows see a
    // truncated descriptor -> "Unknown USB Device (Invalid Configuration
    // Descriptor)". Same pattern as CDC_GetInterface().
    return (int)USBDevice.sendControl(block, (uint32_t)(p - block));
}

int SoteriaU2F::HIDModule::getDescriptor(USBSetup& setup) {
    if (setup.wValueH == 0x22 && (uint8_t)setup.wIndex == pluggedInterface) {
        static const uint8_t reportDesc[] = {
            0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01,
            0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08,
            0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00,
            0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02,
            0xC0
        };
        uint8_t len = sizeof(reportDesc);
        if (setup.wLength < len) len = (uint8_t)setup.wLength;
        USBDevice.sendControl(reportDesc, len);
        return 1;
    }
    return 0;
}

bool SoteriaU2F::HIDModule::setup(USBSetup& setup) {
    if ((setup.bmRequestType & REQUEST_TYPE) == REQUEST_CLASS &&
        (setup.bmRequestType & REQUEST_RECIPIENT) == REQUEST_INTERFACE &&
        (uint8_t)setup.wIndex == pluggedInterface) {
        if (setup.bRequest == 0x0A || setup.bRequest == 0x0B) { // SET_IDLE / SET_PROTOCOL
            USBDevice.sendZlp(0);
            return true;
        }
    }
    return false;
}

bool SoteriaU2F::sendReport(const uint8_t* data, uint8_t len) {
    if (len > 64) len = 64;
    return USBDevice.send(_epIn, data, len) == len;
}

int SoteriaU2F::recvReport(uint8_t* buf, uint8_t maxLen) {
    if (maxLen > 64) maxLen = 64;
    if (!USBDevice.available(_epOut)) return 0;
    return (int)USBDevice.recv(_epOut, buf, maxLen);
}
#endif // SOTERIA_HAS_PLUGGABLE_USB

/* ------------------------------------------------------------------ */
/* SoteriaU2F                                                         */
/* ------------------------------------------------------------------ */

SoteriaU2F::SoteriaU2F()
#ifdef SOTERIA_HAS_PLUGGABLE_USB
    : _epIn(0), _epOut(0), _rxGot(0), _rxExpected(0), _rxSeq(0), _rxCmd(0),
      _rxCid(0), _rxStart(0), _rxActive(false), _nextCid(0x01000001UL),
      _signCount(0)
#endif
{
#ifdef SOTERIA_HAS_PLUGGABLE_USB
    // _hid was constructed (plug() ran) before this body; copy the assigned
    // endpoint number into SoteriaU2F's members.
    _epIn  = _hid.endpointNumber();       // IN endpoint number
    _epOut = _hid.endpointNumber() + 1;   // OUT endpoint number
#endif
    for (int i = 0; i < 4; i++) {
        memset(&_creds[i], 0, sizeof(_creds[i]));
        _creds[i].inUse = false;
    }
}

bool SoteriaU2F::begin() {
    // PluggableUSB().plug() was already invoked from the HIDModule
    // constructor (before main() -> USBDevice.init()). Here we only report
    // whether the HID interface is available on this core.
#ifdef SOTERIA_HAS_PLUGGABLE_USB
    return _epIn != 0 || _epOut != 0;
#else
    return false;
#endif
}

void SoteriaU2F::poll() {
#ifdef SOTERIA_HAS_PLUGGABLE_USB
    // Abandon a message whose continuation packets stopped arriving so a
    // single lost packet cannot wedge the transport forever.
    if (_rxActive && (millis() - _rxStart) > 3000) {
        _rxActive = false;
    }

    // The OUT endpoint NAKs while an unread report sits in its bank, so
    // this loop drains at most what the host has managed to queue up.
    int n;
    while ((n = recvReport(_rxPkt, sizeof(_rxPkt))) > 0) {
        ctaphidPacket(_rxPkt, (uint8_t)n);
    }
#endif
}

// Everything below — CTAPHID framing, CBOR and the CTAP2 commands — only
// exists on builds with the PluggableUSB HID interface; the mzeroproUSB
// environment has no interrupt endpoints to carry any of it.
#ifdef SOTERIA_HAS_PLUGGABLE_USB

/* ------------------------------------------------------------------ */
/* CTAPHID transport                                                   */
/*                                                                     */
/* Packet layout (64-byte HID reports):                                */
/*   init:  cid(4) | cmd|0x80(1) | bcnt(2) | payload(<=57)             */
/*   cont:  cid(4) | seq(1)     | payload(<=59)                        */
/* Responses are always framed back on the channel of the request.     */
/* ------------------------------------------------------------------ */

void SoteriaU2F::ctaphidPacket(const uint8_t* pkt, uint8_t len) {
    if (len < 5) return;

    uint32_t cid = ((uint32_t)pkt[0] << 24) | ((uint32_t)pkt[1] << 16) |
                   ((uint32_t)pkt[2] << 8)  |  (uint32_t)pkt[3];
    uint8_t b4 = pkt[4];

    if (b4 & CTAPHID_TYPE_INIT) {
        // ---- initialization packet: first packet of a message ----
        if (len < 7) return;   // not even room for bcnt
        uint8_t  cmd   = b4;
        uint16_t bcnt  = ((uint16_t)pkt[5] << 8) | pkt[6];
        uint16_t avail = (uint16_t)(len - 7);

        if (cmd == CTAPHID_CMD_INIT) {
            // INIT is single-packet by spec and the one command allowed on
            // the broadcast channel; answer it immediately.
            if (bcnt < 8 || avail < 8) {
                ctaphidSendError(cid, CTAPHID_ERR_INVALID_LEN);
                return;
            }
            ctaphidInit(cid, pkt + 7);
            return;
        }
        if (cid == CTAPHID_CID_BROADCAST) {
            ctaphidSendError(cid, CTAPHID_ERR_INVALID_CID);
            return;
        }
        if (_rxActive && cid != _rxCid) {
            return;   // another channel talking mid-message: ignore per spec
        }
        if (bcnt > sizeof(_rxFrame)) {
            ctaphidSendError(cid, CTAPHID_ERR_INVALID_LEN);
            return;
        }

        // New message: remember the header and the first payload chunk.
        // An init packet always (re)starts reassembly, which also lets a
        // host recover from a previous abandoned transfer.
        _rxCid      = cid;
        _rxCmd      = cmd;
        _rxExpected = bcnt;
        _rxGot      = 0;
        _rxSeq      = 0;
        _rxActive   = true;
        _rxStart    = millis();

        uint16_t copy = avail;
        if (copy > _rxExpected) copy = _rxExpected;
        memcpy(_rxFrame, pkt + 7, copy);
        _rxGot = copy;
        if (_rxGot == _rxExpected) ctaphidMessageDone();
        return;
    }

    // ---- continuation packet ----
    if (!_rxActive || cid != _rxCid) {
        ctaphidSendError(cid, CTAPHID_ERR_INVALID_CID);
        return;
    }
    if (b4 != _rxSeq) {
        _rxActive = false;
        ctaphidSendError(cid, CTAPHID_ERR_INVALID_SEQ);
        return;
    }
    _rxSeq++;

    uint16_t remain = (uint16_t)(_rxExpected - _rxGot);
    uint16_t copy = (uint16_t)(len - 5);
    if (copy > remain) copy = remain;
    memcpy(_rxFrame + _rxGot, pkt + 5, copy);
    _rxGot = (uint16_t)(_rxGot + copy);
    if (_rxGot == _rxExpected) ctaphidMessageDone();
}

void SoteriaU2F::ctaphidMessageDone() {
    _rxActive = false;
    ctaphidDispatch(_rxCmd, _rxFrame, _rxGot);
}

void SoteriaU2F::ctaphidSend(uint32_t cid, uint8_t cmd, const uint8_t* data, uint16_t len) {
    uint8_t frame[64];

    frame[0] = (uint8_t)(cid >> 24);
    frame[1] = (uint8_t)(cid >> 16);
    frame[2] = (uint8_t)(cid >> 8);
    frame[3] = (uint8_t)cid;
    frame[4] = (uint8_t)(CTAPHID_TYPE_INIT | cmd);
    frame[5] = (uint8_t)(len >> 8);
    frame[6] = (uint8_t)(len & 0xFF);

    // First packet carries up to 57 payload bytes. Always ship a full
    // 64-byte report: hosts pad/trim against bcnt themselves.
    uint16_t n = len;
    if (n > 57) n = 57;
    if (data && n) memcpy(frame + 7, data, n);
    memset(frame + 7 + n, 0, 57 - n);
    sendReport(frame, 64);

    // Continuation packets: cid | seq | up to 59 payload bytes each.
    uint16_t off = n;
    uint8_t  seq = 0;
    while (off < len) {
        frame[4] = seq++;
        n = (uint16_t)(len - off);
        if (n > 59) n = 59;
        memcpy(frame + 5, data + off, n);
        memset(frame + 5 + n, 0, 59 - n);
        sendReport(frame, 64);
        off = (uint16_t)(off + n);
    }
}

void SoteriaU2F::ctaphidSendError(uint32_t cid, uint8_t err) {
    ctaphidSend(cid, CTAPHID_CMD_ERROR, &err, 1);
}

void SoteriaU2F::ctaphidSendKeepalive(uint32_t cid, uint8_t status) {
    ctaphidSend(cid, CTAPHID_CMD_KEEPALIVE, &status, 1);
}

void SoteriaU2F::ctaphidInit(uint32_t cid, const uint8_t* nonce) {
    // 17-byte payload: nonce echo (8) | assigned channel (4) |
    // CTAPHID protocol version (1) | device version (3) | capabilities (1).
    uint8_t resp[17];
    memcpy(resp, nonce, 8);

    uint32_t assigned;
    if (cid == CTAPHID_CID_BROADCAST) {
        _nextCid++;
        if (_nextCid == 0 || _nextCid == CTAPHID_CID_BROADCAST) _nextCid = 0x01000001UL;
        assigned = _nextCid;
    } else {
        assigned = cid;   // keep the channel the host already thinks it has
    }
    resp[8]  = (uint8_t)(assigned >> 24);
    resp[9]  = (uint8_t)(assigned >> 16);
    resp[10] = (uint8_t)(assigned >> 8);
    resp[11] = (uint8_t)assigned;
    resp[12] = 0x01;   // CTAPHID protocol version
    resp[13] = 1;       // device version 1.0.0
    resp[14] = 0;
    resp[15] = 0;
    resp[16] = (uint8_t)(CTAPHID_CAP_CBOR | CTAPHID_CAP_NMSG);

    // The *packet* always answers on the request's channel (broadcast for
    // a broadcast INIT); the freshly allocated channel travels inside the
    // payload. python-fido2 and Windows reject any other layout.
    ctaphidSend(cid, CTAPHID_CMD_INIT, resp, sizeof(resp));
}

void SoteriaU2F::ctaphidDispatch(uint8_t cmd, const uint8_t* data, uint16_t len) {
    switch (cmd) {
        case CTAPHID_CMD_PING:
            ctaphidSend(_rxCid, CTAPHID_CMD_PING, data, len);
            break;

        case CTAPHID_CMD_CBOR:
            ctap2Dispatch(data, len);
            break;

        case CTAPHID_CMD_MSG:
            // CTAP1/U2F is not implemented (CTAPHID_CAP_NMSG says so);
            // still answer with the U2F "instruction not supported" status
            // word so legacy clients fail fast instead of hanging.
            ctaphidSend(_rxCid, CTAPHID_CMD_MSG, (const uint8_t*)"\x6D\x00", 2);
            break;

        case CTAPHID_CMD_INIT:
            // Handled directly in ctaphidPacket(); never dispatched.
            break;

        case CTAPHID_CMD_CANCEL:
        case CTAPHID_CMD_KEEPALIVE:
            // poll() runs everything to completion synchronously, so there
            // is never a request in flight to cancel.
            break;

        default:
            ctaphidSendError(_rxCid, CTAPHID_ERR_INVALID_CMD);
            break;
    }
}

/* ------------------------------------------------------------------ */
/* Minimal CBOR (RFC 7049)                                             */
/*                                                                     */
/* Reader: every parse is bounded by the caller's end pointer, so a     */
/* malformed request can never make us read outside _rxFrame.           */
/* ------------------------------------------------------------------ */

struct CborHead {
    const uint8_t* data;   // first byte after the head
    uint8_t  major;
    uint64_t arg;          // value/length/count; for major 7 the subtype
    bool     indef;
};

// Parse the CBOR head at p; h.data points just past it.
static bool cborHead(const uint8_t* p, const uint8_t* end, CborHead& h) {
    if (p >= end) return false;
    uint8_t b = *p++;
    h.major = (uint8_t)(b >> 5);
    uint8_t ai = (uint8_t)(b & 0x1F);
    h.indef = false;
    h.data = p;
    if (ai < 24) { h.arg = ai; return true; }
    if (ai == 31) {
        // Indefinite length (majors 2-5); major 7 ai=31 is the break code.
        h.arg = 31;
        h.indef = (h.major >= 2 && h.major <= 5);
        return true;
    }
    uint8_t width = (ai == 24) ? 1 : (ai == 25) ? 2 : (ai == 26) ? 4 : (ai == 27) ? 8 : 0;
    if (width == 0 || (uint32_t)(end - p) < width) return false;  // ai 28-30 reserved
    uint64_t v = 0;
    for (uint8_t i = 0; i < width; i++) v = (v << 8) | *p++;
    h.arg = v;
    h.data = p;
    return true;
}

// Return the pointer just past the complete item at p (NULL if malformed).
static const uint8_t* cborSkip(const uint8_t* p, const uint8_t* end) {
    CborHead h;
    if (!cborHead(p, end, h)) return nullptr;
    if (h.major == 0 || h.major == 1 || h.major == 7) return h.data;
    if (h.major == 6) return cborSkip(h.data, end);          // tag: value follows
    if (h.indef) {
        const uint8_t* q = h.data;
        while (q < end) {
            if (*q == 0xFF) return q + 1;
            q = cborSkip(q, end);
            if (!q) return nullptr;
        }
        return nullptr;
    }
    if (h.major <= 3) {
        if (h.arg > (uint64_t)(end - h.data)) return nullptr;
        return h.data + h.arg;
    }
    if (h.arg > 1024) return nullptr;                        // absurd item counts
    const uint8_t* q = h.data;
    uint64_t n = (h.major == 4) ? h.arg : h.arg * 2;         // array / map items
    for (uint64_t i = 0; i < n; i++) {
        q = cborSkip(q, end);
        if (!q) return nullptr;
    }
    return q;
}

// A fully parsed CBOR item.
struct CborVal {
    const uint8_t* head;   // start of the item
    const uint8_t* data;   // contents (after the head)
    const uint8_t* end;    // one past the item
    uint8_t  major;
    uint64_t arg;
    bool     indef;
};

static bool cborItem(const uint8_t* p, const uint8_t* end, CborVal& v) {
    CborHead h;
    if (!cborHead(p, end, h)) return false;
    const uint8_t* e = cborSkip(p, end);
    if (!e) return false;
    v.head = p;
    v.data = h.data;
    v.end = e;
    v.major = h.major;
    v.arg = h.arg;
    v.indef = h.indef;
    return true;
}

// Find a key inside the CBOR map at p. wantKey points at a uint64_t for
// integer keys or at a NUL-terminated string for text keys.
static bool cborMapFind(const uint8_t* p, const uint8_t* end, const void* wantKey,
                        bool textKey, CborVal& v) {
    CborHead map;
    if (!cborHead(p, end, map)) return false;
    if (!map.indef && map.major != 5) return false;
    const uint8_t* mapEnd = cborSkip(p, end);
    if (!mapEnd) return false;

    const uint8_t* q = map.data;
    uint64_t pairs = map.indef ? ~0ULL : map.arg;
    for (uint64_t i = 0; i < pairs; i++) {
        if (map.indef && (q >= mapEnd || *q == 0xFF)) break;   // end of map
        CborVal key;
        if (!cborItem(q, mapEnd, key)) return false;
        bool match = false;
        if (textKey && key.major == 3 && !key.indef) {
            const char* s = (const char*)wantKey;
            size_t n = strlen(s);
            match = (key.arg == n && memcmp(key.data, s, n) == 0);
        } else if (!textKey && key.major == 0 && !key.indef) {
            match = (key.arg == *(const uint64_t*)wantKey);
        }
        CborVal val;
        if (!cborItem(key.end, mapEnd, val)) return false;
        if (match) { v = val; return true; }
        q = val.end;
    }
    return false;
}

static bool cborMapGetUint(const uint8_t* p, const uint8_t* end, uint64_t key, CborVal& v) {
    return cborMapFind(p, end, &key, false, v);
}
static bool cborMapGetText(const uint8_t* p, const uint8_t* end, const char* key, CborVal& v) {
    return cborMapFind(p, end, key, true, v);
}

// Fetch element `index` of the CBOR array described by arr.
static bool cborArrayGet(const CborVal& arr, uint64_t index, CborVal& v) {
    if (arr.major != 4 && !arr.indef) return false;
    const uint8_t* q = arr.data;
    uint64_t n = arr.indef ? ~0ULL : arr.arg;
    for (uint64_t i = 0; i < n; i++) {
        if (arr.indef && (q >= arr.end || *q == 0xFF)) return false;
        if (!cborItem(q, arr.end, v)) return false;
        if (i == index) return true;
        q = v.end;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* CBOR writer                                                         */
/*                                                                     */
/* CTAP responses must survive strict canonical re-encoding on the     */
/* host side (python-fido2 defaults strict_cbor=True), so: shortest    */
/* integer/length forms, definite lengths, and map keys emitted in      */
/* ascending order of their encoded bytes.                             */
/* ------------------------------------------------------------------ */

struct CborOut {
    uint8_t* buf;
    uint16_t cap;
    uint16_t len;
    bool     ok;
};

static void cbInit(CborOut& o, uint8_t* buf, uint16_t cap) {
    o.buf = buf; o.cap = cap; o.len = 0; o.ok = true;
}

static void cbHead(CborOut& o, uint8_t major, uint64_t arg) {
    if (!o.ok) return;
    uint8_t tmp[9];
    uint8_t n = 1;
    if (arg < 24) {
        tmp[0] = (uint8_t)((major << 5) | arg);
    } else if (arg <= 0xFF) {
        tmp[0] = (uint8_t)((major << 5) | 24);
        tmp[1] = (uint8_t)arg;
        n = 2;
    } else if (arg <= 0xFFFF) {
        tmp[0] = (uint8_t)((major << 5) | 25);
        tmp[1] = (uint8_t)(arg >> 8);
        tmp[2] = (uint8_t)arg;
        n = 3;
    } else if (arg <= 0xFFFFFFFFULL) {
        tmp[0] = (uint8_t)((major << 5) | 26);
        tmp[1] = (uint8_t)(arg >> 24);
        tmp[2] = (uint8_t)(arg >> 16);
        tmp[3] = (uint8_t)(arg >> 8);
        tmp[4] = (uint8_t)arg;
        n = 5;
    } else {
        tmp[0] = (uint8_t)((major << 5) | 27);
        for (uint8_t i = 0; i < 8; i++) tmp[1 + i] = (uint8_t)(arg >> (56 - 8 * i));
        n = 9;
    }
    if ((uint32_t)o.len + n > o.cap) { o.ok = false; return; }
    memcpy(o.buf + o.len, tmp, n);
    o.len = (uint16_t)(o.len + n);
}

static void cbUint(CborOut& o, uint64_t v)   { cbHead(o, 0, v); }
static void cbInt(CborOut& o, int64_t v) {
    if (v >= 0) cbHead(o, 0, (uint64_t)v);
    else cbHead(o, 1, (uint64_t)(-1 - v));
}
static void cbMap(CborOut& o, uint32_t n)    { cbHead(o, 5, n); }
static void cbArray(CborOut& o, uint32_t n)  { cbHead(o, 4, n); }

static void cbRaw(CborOut& o, const uint8_t* d, uint32_t n) {
    if (!o.ok) return;
    if ((uint32_t)o.len + n > o.cap) { o.ok = false; return; }
    if (d && n) memcpy(o.buf + o.len, d, n);
    o.len = (uint16_t)(o.len + n);
}
static void cbBytes(CborOut& o, const uint8_t* d, uint32_t n) {
    cbHead(o, 2, n);
    cbRaw(o, d, n);
}
static void cbTextN(CborOut& o, const char* s, uint32_t n) {
    cbHead(o, 3, n);
    cbRaw(o, (const uint8_t*)s, n);
}
static void cbText(CborOut& o, const char* s) { cbTextN(o, s, (uint32_t)strlen(s)); }
static void cbBool(CborOut& o, bool b) {
    if (!o.ok) return;
    if ((uint32_t)o.len + 1 > o.cap) { o.ok = false; return; }
    o.buf[o.len++] = b ? 0xF5 : 0xF4;
}

/* ------------------------------------------------------------------ */
/* Deterministic ECDSA (RFC 6979) over P-256                           */
/*                                                                     */
/* micro-ecc drives uECC_HashContext with init/update/finish calls,     */
/* never feeding more than ~100 bytes per run, while utils.h only       */
/* offers a one-shot sha256(). So buffer each run and hash it at        */
/* finish(). tmp[] is the scratch the HMAC-DRBG requires:               */
/* K(32) | V(32) | ipad/opad block(64).                                 */
/* ------------------------------------------------------------------ */

struct SoteriaHashCtx {
    uECC_HashContext base;      // must come first: cast target
    uint8_t tmp[2 * 32 + 64];
    uint8_t buf[256];
    unsigned len;
    bool     bad;
};

static void soteriaHashInit(const uECC_HashContext* c) {
    ((SoteriaHashCtx*)c)->len = 0;
}
static void soteriaHashUpdate(const uECC_HashContext* c, const uint8_t* data, unsigned n) {
    SoteriaHashCtx* s = (SoteriaHashCtx*)c;
    if (s->len + n > sizeof(s->buf)) { s->bad = true; return; }   // cannot happen
    memcpy(s->buf + s->len, data, n);
    s->len += n;
}
static void soteriaHashFinish(const uECC_HashContext* c, uint8_t* out) {
    SoteriaHashCtx* s = (SoteriaHashCtx*)c;
    sha256(s->buf, s->len, out);
}

// DER INTEGER with minimal length and a 0x00 pad when the high bit is set.
static uint8_t* derInt(uint8_t* p, const uint8_t* v, uint32_t n) {
    while (n > 1 && *v == 0) { v++; n--; }
    bool pad = (v[0] & 0x80) != 0;
    *p++ = 0x02;
    *p++ = (uint8_t)(n + (pad ? 1 : 0));
    if (pad) *p++ = 0x00;
    memcpy(p, v, n);
    return p + n;
}

// SEQUENCE { INTEGER r, INTEGER s } — the encoding WebAuthn verifiers expect.
static bool ecdsaDer(const uint8_t r[32], const uint8_t s[32], uint8_t* out, uint8_t* outLen) {
    uint8_t seq[72];
    uint8_t* p = derInt(seq, r, 32);
    p = derInt(p, s, 32);
    uint32_t inner = (uint32_t)(p - seq);
    if (inner > 127) return false;
    out[0] = 0x30;
    out[1] = (uint8_t)inner;
    memcpy(out + 2, seq, inner);
    *outLen = (uint8_t)(2 + inner);
    return true;
}

// Sign hash[32] with priv[32]; writes a DER signature (<=72 bytes) to der.
static bool ecdsaSign(const uint8_t priv[32], const uint8_t hash[32],
                      uint8_t* der, uint8_t* derLen) {
    static SoteriaHashCtx ctx;   // ~420 B: kept off the stack

    ctx.base.init_hash = soteriaHashInit;
    ctx.base.update_hash = soteriaHashUpdate;
    ctx.base.finish_hash = soteriaHashFinish;
    ctx.base.result_size = 32;
    ctx.base.block_size = 64;
    ctx.base.tmp = ctx.tmp;
    ctx.len = 0;
    ctx.bad = false;

    uint8_t sig[64];   // r || s, big-endian
    if (!uECC_sign_deterministic(priv, hash, 32, &ctx.base, sig, uECC_secp256r1()))
        return false;
    if (ctx.bad) return false;
    return ecdsaDer(sig, sig + 32, der, derLen);
}

/* ------------------------------------------------------------------ */
/* CTAP2 commands                                                      */
/*                                                                     */
/* Success responses are 0x00 + CBOR; errors are a single status byte.  */
/* All maps are emitted with keys in ascending encoded-byte order so    */
/* hosts that strictly re-encode (python-fido2 default) accept them.    */
/* ------------------------------------------------------------------ */

#define CTAP2_OK                    0x00
#define CTAP2_ERR_INVALID_CMD       0x01
#define CTAP2_ERR_INVALID_LEN       0x03
#define CTAP2_ERR_INVALID_CBOR      0x12
#define CTAP2_ERR_MISSING_PARAMETER 0x14
#define CTAP2_ERR_CREDENTIAL_EXCLUDED 0x19
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM 0x26
#define CTAP2_ERR_KEY_STORE_FULL    0x28
#define CTAP2_ERR_INVALID_OPTION    0x2C
#define CTAP2_ERR_NO_CREDENTIALS    0x2E
#define CTAP2_ERR_OTHER             0x7F

// Fixed device-wide AAGUID: "soteria\0WALLET01".
static const uint8_t SOTERIA_AAGUID[16] = {
    's', 'o', 't', 'e', 'r', 'i', 'a', 0,
    'W', 'A', 'L', 'L', 'E', 'T', '0', '1'
};

void SoteriaU2F::ctap2SendStatus(uint8_t code) {
    ctaphidSend(_rxCid, CTAPHID_CMD_CBOR, &code, 1);
}

void SoteriaU2F::ctap2Dispatch(const uint8_t* req, uint16_t reqLen) {
    if (reqLen < 1) { ctap2SendStatus(CTAP2_ERR_INVALID_LEN); return; }

    // Every CTAP2 command except bare getInfo carries a CBOR map payload;
    // reject anything else (including trailing garbage) up front.
    if (reqLen > 1) {
        const uint8_t* end = req + reqLen;
        CborHead h;
        if (!cborHead(req, end, h) || h.major != 5 || cborSkip(req, end) != end) {
            ctap2SendStatus(CTAP2_ERR_INVALID_CBOR);
            return;
        }
    }

    switch (req[0]) {
        case CTAP2_CMD_GET_INFO:
            ctap2GetInfo();
            break;
        case CTAP2_CMD_MAKE_CREDENTIAL:
            ctap2MakeCredential(req + 1, reqLen - 1);
            break;
        case CTAP2_CMD_GET_ASSERTION:
            ctap2GetAssertion(req + 1, reqLen - 1);
            break;
        default:
            ctap2SendStatus(CTAP2_ERR_INVALID_CMD);
            break;
    }
}

void SoteriaU2F::ctap2GetInfo() {
    CborOut o;
    cbInit(o, _txBuf + 1, (uint16_t)(sizeof(_txBuf) - 1));
    cbMap(o, 6);
    cbUint(o, 1); cbArray(o, 1); cbText(o, "FIDO_2_0");   // versions
    cbUint(o, 2); cbArray(o, 0);                           // extensions
    cbUint(o, 3); cbBytes(o, SOTERIA_AAGUID, 16);          // aaguid
    cbUint(o, 4);                                          // options
    cbMap(o, 5);
    cbText(o, "rk");        cbBool(o, false);
    cbText(o, "up");        cbBool(o, true);
    cbText(o, "uv");        cbBool(o, false);
    cbText(o, "plat");      cbBool(o, false);
    cbText(o, "clientPin"); cbBool(o, false);
    cbUint(o, 5); cbUint(o, 1024);                         // maxMsgSize
    cbUint(o, 9); cbArray(o, 1); cbText(o, "usb");         // transports
    if (!o.ok) { ctap2SendStatus(CTAP2_ERR_OTHER); return; }

    _txBuf[0] = CTAP2_OK;
    ctaphidSend(_rxCid, CTAPHID_CMD_CBOR, _txBuf, (uint16_t)(o.len + 1));
}

void SoteriaU2F::ctap2MakeCredential(const uint8_t* req, uint16_t reqLen) {
    const uint8_t* end = req + reqLen;
    CborHead hdr;
    if (!cborHead(req, end, hdr) || hdr.major != 5) {
        ctap2SendStatus(CTAP2_ERR_INVALID_CBOR);
        return;
    }

    CborVal v;

    // 1: clientDataHash — 32-byte string
    if (!cborMapGetUint(req, end, 1, v) || v.major != 2 || v.indef || v.arg != 32) {
        ctap2SendStatus(CTAP2_ERR_MISSING_PARAMETER);
        return;
    }
    const uint8_t* clientDataHash = v.data;

    // 2: rp -> "id"; the hash of the RP id is what the signature covers
    if (!cborMapGetUint(req, end, 2, v) || (v.major != 5 && !v.indef)) {
        ctap2SendStatus(CTAP2_ERR_MISSING_PARAMETER);
        return;
    }
    CborVal rpId;
    if (!cborMapGetText(v.head, v.end, "id", rpId) || rpId.major != 3 || rpId.indef ||
        rpId.arg == 0 || rpId.arg > 253) {
        ctap2SendStatus(CTAP2_ERR_MISSING_PARAMETER);
        return;
    }
    uint8_t rpIdHash[32];
    sha256(rpId.data, (size_t)rpId.arg, rpIdHash);

    // 3: user -> id / name / displayName
    if (!cborMapGetUint(req, end, 3, v) || (v.major != 5 && !v.indef)) {
        ctap2SendStatus(CTAP2_ERR_MISSING_PARAMETER);
        return;
    }
    CborVal uId, uName, uDisp;
    if (!cborMapGetText(v.head, v.end, "id", uId) || uId.major != 2 || uId.indef ||
        uId.arg == 0 || uId.arg > 64 ||
        !cborMapGetText(v.head, v.end, "name", uName) || uName.major != 3 || uName.indef ||
        uName.arg > 64) {
        ctap2SendStatus(CTAP2_ERR_MISSING_PARAMETER);
        return;
    }
    if (!cborMapGetText(v.head, v.end, "displayName", uDisp) || uDisp.major != 3 ||
        uDisp.indef || uDisp.arg > 64) {
        uDisp = uName;   // spec requires it; fall back to "name" if absent
    }

    // 4: pubKeyCredParams must offer ES256 (alg -7)
    if (!cborMapGetUint(req, end, 4, v) || v.major != 4 || v.indef) {
        ctap2SendStatus(CTAP2_ERR_MISSING_PARAMETER);
        return;
    }
    bool algOk = false;
    for (uint64_t i = 0; i < v.arg && i < 32 && !algOk; i++) {
        CborVal el, alg;
        if (!cborArrayGet(v, i, el)) { ctap2SendStatus(CTAP2_ERR_INVALID_CBOR); return; }
        // pubKeyCredParams entries are JSON-shaped: {"type","alg"} -> text keys
        if (cborMapGetText(el.head, el.end, "alg", alg) && alg.major == 1 && !alg.indef &&
            alg.arg == 6 /* -7 */) {
            algOk = true;
        }
    }
    if (!algOk) { ctap2SendStatus(CTAP2_ERR_UNSUPPORTED_ALGORITHM); return; }

    // 5: excludeList — refuse an rpId+credential id we already hold
    if (cborMapGetUint(req, end, 5, v) && (v.major == 4 || v.indef)) {
        for (uint64_t i = 0; i < v.arg && i < 32; i++) {
            CborVal el, id;
            if (!cborArrayGet(v, i, el)) break;
            if (!cborMapGetText(el.head, el.end, "id", id)) continue;
            if (id.major != 2 || id.indef || id.arg != 32) continue;
            for (int c = 0; c < 4; c++) {
                if (_creds[c].inUse &&
                    memcmp(_creds[c].credId, id.data, 32) == 0 &&
                    memcmp(_creds[c].appId, rpIdHash, 32) == 0) {
                    ctap2SendStatus(CTAP2_ERR_CREDENTIAL_EXCLUDED);
                    return;
                }
            }
        }
    }

    // 7: options — resident keys are unsupported (getInfo advertises rk:false)
    if (cborMapGetUint(req, end, 7, v) && (v.major == 5 || v.indef)) {
        CborVal rk;
        if (cborMapGetText(v.head, v.end, "rk", rk) && rk.major == 7 && rk.arg == 21) {
            ctap2SendStatus(CTAP2_ERR_INVALID_OPTION);
            return;
        }
    }

    // Find a free credential slot (credentials are RAM-only on this build)
    int slot = -1;
    for (int i = 0; i < 4; i++) {
        if (!_creds[i].inUse) { slot = i; break; }
    }
    if (slot < 0) { ctap2SendStatus(CTAP2_ERR_KEY_STORE_FULL); return; }

    // Key material: ADC noise folded with rpIdHash + user id + timestamp so
    // every credential differs even if the noise source misbehaves. RNGpin
    // polls analogRead() until the pin toggles, so warn the host first.
    ctaphidSendKeepalive(_rxCid, 0x01);   // 0x01 = processing
    uint8_t priv[32];
    RNGpin(_txBuf, 32);
    memcpy(_txBuf + 32, rpIdHash, 32);
    memcpy(_txBuf + 64, uId.data, (size_t)uId.arg);
    uint32_t now = millis();
    memcpy(_txBuf + 64 + uId.arg, &now, 4);
    sha256(_txBuf, 68 + (size_t)uId.arg, priv);
    priv[0] &= 0xF8;    // keep the scalar inside [2^254, 2^255): nonzero and < n
    priv[31] &= 0x7F;
    priv[31] |= 0x40;

    uint8_t pub[64];    // uncompressed P-256 point: x || y
    if (!uECC_compute_public_key(priv, pub, uECC_secp256r1())) {
        ctap2SendStatus(CTAP2_ERR_OTHER);
        return;
    }
    ctaphidSendKeepalive(_rxCid, 0x01);

    // Credential id: SHA-256(priv || rpIdHash) — opaque, unique per rp.
    memcpy(_txBuf, priv, 32);
    memcpy(_txBuf + 32, rpIdHash, 32);
    uint8_t credId[32];
    sha256(_txBuf, 64, credId);

    // Authenticator data:
    //   rpIdHash(32) | flags(1) | signCount(4) | attestedCredData
    //   attestedCredData = aaguid(16) | credIdLen(2) | credId | COSE key
    _signCount++;
    uint8_t authData[196];
    memcpy(authData, rpIdHash, 32);
    authData[32] = 0x41;    // UP (0x01) | AT (0x40)
    authData[33] = (uint8_t)(_signCount >> 24);
    authData[34] = (uint8_t)(_signCount >> 16);
    authData[35] = (uint8_t)(_signCount >> 8);
    authData[36] = (uint8_t)_signCount;
    uint8_t* p = authData + 37;
    memcpy(p, SOTERIA_AAGUID, 16); p += 16;
    *p++ = 0; *p++ = 32;                    // credential id length (BE)
    memcpy(p, credId, 32); p += 32;
    *p++ = 0xA5;                            // COSE_Key, map(5)
    *p++ = 0x01; *p++ = 0x02;               //  1: kty = EC2
    *p++ = 0x03; *p++ = 0x26;               //  3: alg = ES256 (-7)
    *p++ = 0x20; *p++ = 0x01;               // -1: crv = P-256
    *p++ = 0x21; *p++ = 0x58; *p++ = 0x20;  // -2: x
    memcpy(p, pub, 32); p += 32;
    *p++ = 0x22; *p++ = 0x58; *p++ = 0x20;  // -3: y
    memcpy(p, pub + 32, 32); p += 32;
    uint16_t authLen = (uint16_t)(p - authData);   // 164 bytes

    // packed self-attestation (no x5c): sig = ECDSA(authData || clientDataHash)
    memcpy(authData + authLen, clientDataHash, 32);
    uint8_t hash[32];
    sha256(authData, authLen + 32, hash);
    uint8_t sig[76], sigLen = 0;
    if (!ecdsaSign(priv, hash, sig, &sigLen)) {
        ctap2SendStatus(CTAP2_ERR_OTHER);
        return;
    }

    // Everything succeeded — publish the credential.
    U2fCredential* c = &_creds[slot];
    memset(c, 0, sizeof(*c));
    c->inUse = true;
    c->keyHandleLen = 32;
    memcpy(c->keyHandle, priv, 32);
    memcpy(c->publicKey, pub, 64);
    memcpy(c->appId, rpIdHash, 32);
    memcpy(c->credId, credId, 32);
    memcpy(c->userId, uId.data, (size_t)uId.arg);
    c->userIdLen = (uint8_t)uId.arg;
    memcpy(c->userName, uName.data, (size_t)uName.arg);
    c->userNameLen = (uint8_t)uName.arg;
    memcpy(c->userDisplay, uDisp.data, (size_t)uDisp.arg);
    c->userDisplayLen = (uint8_t)uDisp.arg;

    // {1: "packed", 2: authData, 3: {"alg": -7, "sig": ...}}
    CborOut o;
    cbInit(o, _txBuf + 1, (uint16_t)(sizeof(_txBuf) - 1));
    cbMap(o, 3);
    cbUint(o, 1); cbText(o, "packed");
    cbUint(o, 2); cbBytes(o, authData, authLen);
    cbUint(o, 3);
    cbMap(o, 2);
    cbText(o, "alg"); cbInt(o, -7);
    cbText(o, "sig"); cbBytes(o, sig, sigLen);
    if (!o.ok) { ctap2SendStatus(CTAP2_ERR_OTHER); return; }

    _txBuf[0] = CTAP2_OK;
    ctaphidSend(_rxCid, CTAPHID_CMD_CBOR, _txBuf, (uint16_t)(o.len + 1));
}

void SoteriaU2F::ctap2GetAssertion(const uint8_t* req, uint16_t reqLen) {
    const uint8_t* end = req + reqLen;
    CborHead hdr;
    if (!cborHead(req, end, hdr) || hdr.major != 5) {
        ctap2SendStatus(CTAP2_ERR_INVALID_CBOR);
        return;
    }

    CborVal v;

    // 1: rpId
    if (!cborMapGetUint(req, end, 1, v) || v.major != 3 || v.indef ||
        v.arg == 0 || v.arg > 253) {
        ctap2SendStatus(CTAP2_ERR_MISSING_PARAMETER);
        return;
    }
    uint8_t rpIdHash[32];
    sha256(v.data, (size_t)v.arg, rpIdHash);

    // 2: clientDataHash
    if (!cborMapGetUint(req, end, 2, v) || v.major != 2 || v.indef || v.arg != 32) {
        ctap2SendStatus(CTAP2_ERR_MISSING_PARAMETER);
        return;
    }
    const uint8_t* clientDataHash = v.data;

    // Select the credential: by allowList id if one was given, otherwise
    // any credential belonging to this rpId (getInfo advertises rk:false,
    // so well-behaved platforms always send an allowList).
    U2fCredential* cred = nullptr;
    bool fromAllowList = false;
    if (cborMapGetUint(req, end, 3, v) && (v.major == 4 || v.indef)) {
        fromAllowList = true;
        for (uint64_t i = 0; i < v.arg && i < 32; i++) {
            CborVal el, id;
            if (!cborArrayGet(v, i, el)) break;
            if (!cborMapGetText(el.head, el.end, "id", id)) continue;
            if (id.major != 2 || id.indef || id.arg != 32) continue;
            for (int c = 0; c < 4; c++) {
                if (_creds[c].inUse && memcmp(_creds[c].credId, id.data, 32) == 0) {
                    cred = &_creds[c];
                    break;
                }
            }
            if (cred) break;
        }
    } else {
        for (int c = 0; c < 4; c++) {
            if (_creds[c].inUse && memcmp(_creds[c].appId, rpIdHash, 32) == 0) {
                cred = &_creds[c];
                break;
            }
        }
    }
    if (!cred) { ctap2SendStatus(CTAP2_ERR_NO_CREDENTIALS); return; }

    // options (key 5): up/uv are not enforced on this MVP build — no button
    // or biometric check exists, and platforms learn uv:false from getInfo.

    // Authenticator data: rpIdHash(32) | flags(UP) | signCount(4) | hash(32)
    _signCount++;
    uint8_t authData[69];
    memcpy(authData, rpIdHash, 32);
    authData[32] = 0x01;
    authData[33] = (uint8_t)(_signCount >> 24);
    authData[34] = (uint8_t)(_signCount >> 16);
    authData[35] = (uint8_t)(_signCount >> 8);
    authData[36] = (uint8_t)_signCount;
    memcpy(authData + 37, clientDataHash, 32);

    uint8_t hash[32];
    sha256(authData, 69, hash);
    uint8_t sig[76], sigLen = 0;
    if (!ecdsaSign(cred->keyHandle, hash, sig, &sigLen)) {
        ctap2SendStatus(CTAP2_ERR_OTHER);
        return;
    }

    // {1: credential, 2: authData, 3: signature [, 4: user]}
    CborOut o;
    cbInit(o, _txBuf + 1, (uint16_t)(sizeof(_txBuf) - 1));
    cbMap(o, fromAllowList ? 3 : 4);
    cbUint(o, 1);                                  // credential
    cbMap(o, 2);
    cbText(o, "id");   cbBytes(o, cred->credId, 32);
    cbText(o, "type"); cbText(o, "public-key");
    cbUint(o, 2); cbBytes(o, authData, 37);        // authData
    cbUint(o, 3); cbBytes(o, sig, sigLen);         // signature
    if (!fromAllowList) {
        cbUint(o, 4);                              // user (discoverable case)
        cbMap(o, 3);
        cbText(o, "id");          cbBytes(o, cred->userId, cred->userIdLen);
        cbText(o, "name");        cbTextN(o, (const char*)cred->userName, cred->userNameLen);
        cbText(o, "displayName"); cbTextN(o, (const char*)cred->userDisplay, cred->userDisplayLen);
    }
    if (!o.ok) { ctap2SendStatus(CTAP2_ERR_OTHER); return; }

    _txBuf[0] = CTAP2_OK;
    ctaphidSend(_rxCid, CTAPHID_CMD_CBOR, _txBuf, (uint16_t)(o.len + 1));
}

#endif // SOTERIA_HAS_PLUGGABLE_USB

U2fCredential* SoteriaU2F::credentialAt(int index) {
    if (index < 0 || index >= 4) return nullptr;
    return &_creds[index];
}

SoteriaU2F gU2F;
