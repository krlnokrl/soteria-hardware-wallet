#include "buttons.h"
#include "wallet.h"

#define DEBOUNCE_MS 25

struct ButtonState {
    uint8_t  pin;
    bool     raw;       // last sampled level
    bool     stable;    // debounced level
    uint32_t since;     // millis() of the last raw change
    bool     armed;     // released since buttonsArm(): a press may count
};

static ButtonState s_buttons[2] = {
    { YES, false, false, 0, false },
    { NO,  false, false, 0, false },
};

void buttonsArm() {
    for (ButtonState &b : s_buttons) {
        b.raw = b.stable = digitalRead(b.pin);
        b.since = millis();
        b.armed = !b.stable;
    }
}

// Update one button; true on a debounced, armed press.
static bool sample(ButtonState &b) {
    bool level = digitalRead(b.pin);
    uint32_t now = millis();
    if (level != b.raw) {
        b.raw = level;
        b.since = now;
        return false;
    }
    if (level == b.stable || now - b.since < DEBOUNCE_MS) return false;
    b.stable = level;
    if (!level) {
        b.armed = true;
        return false;
    }
    bool pressed = b.armed;
    b.armed = false;
    return pressed;
}

Button buttonsPoll() {
    bool yes = sample(s_buttons[0]);
    bool no = sample(s_buttons[1]);
    if (yes) return BTN_YES;
    if (no) return BTN_NO;
    return BTN_NONE;
}
