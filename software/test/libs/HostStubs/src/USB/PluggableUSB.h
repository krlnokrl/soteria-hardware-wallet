#pragma once
// Host stand-in for the SAMD core's USB API: HID reports go through queues
// that the tests fill and drain (see HostStubs.h).
#include <Arduino.h>
struct USBSetup {
    uint8_t bmRequestType;
    uint8_t bRequest;
    uint8_t wValueL;
    uint8_t wValueH;
    uint16_t wIndex;
    uint16_t wLength;
};
#define REQUEST_TYPE 0x60
#define REQUEST_CLASS 0x20
#define REQUEST_RECIPIENT 0x1F
#define REQUEST_INTERFACE 0x01
#define USB_ENDPOINT_TYPE_INTERRUPT 0x03
#define USB_ENDPOINT_IN(a) ((a) | 0x80)
#define USB_ENDPOINT_OUT(a) (a)

class PluggableUSBModule {
public:
    PluggableUSBModule(uint8_t numEps, uint8_t numIfs, uint32_t *epType)
        : numEndpoints(numEps), numInterfaces(numIfs), endpointType(epType) {}
    virtual ~PluggableUSBModule() {}
    virtual bool setup(USBSetup &setup) = 0;
    virtual int getInterface(uint8_t *interfaceCount) = 0;
    virtual int getDescriptor(USBSetup &setup) = 0;
    uint8_t pluggedInterface = 0;
    uint8_t pluggedEndpoint = 0;
    const uint8_t numEndpoints;
    const uint8_t numInterfaces;
    const uint32_t *endpointType;
};
struct PluggableUSB_ {
    bool plug(PluggableUSBModule *m) { m->pluggedInterface = 2; m->pluggedEndpoint = 4; return true; }
};
PluggableUSB_ &PluggableUSB();

class EPHandler {
public:
    virtual void handleEndpoint() = 0;
    virtual uint32_t recv(void *data, uint32_t len) = 0;
    virtual uint32_t available() const = 0;
    virtual void init() = 0;
};
class USBDevice_SAMD21G18x {
public:
    void epBank0SetAddress(uint32_t, void *) {}
    void epBank0SetSize(uint32_t, uint16_t) {}
    void epBank0SetType(uint32_t, uint8_t) {}
    void epBank0EnableTransferComplete(uint32_t) {}
    void epBank0SetMultiPacketSize(uint32_t, uint16_t) {}
    void epBank0SetByteCount(uint32_t, uint16_t) {}
    void epBank0ResetReady(uint32_t) {}
    uint16_t epBank0ByteCount(uint32_t) { return 0; }
    void epBank0AckTransferComplete(uint32_t) {}
};
class USBDeviceClass {
public:
    void setHandler(uint32_t, EPHandler *) {}
    uint32_t sendControl(const void *, uint32_t len) { return len; }
    void sendZlp(uint32_t) {}
    uint32_t send(uint32_t ep, const void *data, uint32_t len);
    uint32_t recv(uint32_t ep, void *data, uint32_t len);
    uint32_t available(uint32_t ep);
};
extern USBDeviceClass USBDevice;
