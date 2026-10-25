/* Soteria Wallet – Web Serial debug client */

(function () {
  const BAUD = 115200;

  // DOM elements
  const connectBtn = document.getElementById('connect-btn');
  const statusDot = document.querySelector('#status-indicator .dot');
  const statusText = document.getElementById('status-text');
  const portInfo = document.getElementById('port-info');
  const terminal = document.getElementById('terminal');
  const clearBtn = document.getElementById('clear-btn');

  let port = null;
  let writer = null;
  let reader = null;
  let readLoopPromise = null;
  let buffer = '';

  /* ---------- UI helpers ---------- */

  function setConnected(connected, portName = '') {
    if (connected) {
      connectBtn.textContent = 'Disconnect';
      connectBtn.classList.add('connected');
      connectBtn.disabled = false;
      statusDot.className = '';
      statusDot.classList.add('connected-dot');
      statusText.textContent = 'Connected';
      portInfo.textContent = portName ? `Port: ${portName}` : '';
    } else {
      connectBtn.textContent = 'Connect';
      connectBtn.classList.remove('connected');
      connectBtn.disabled = false;
      statusDot.className = '';
      statusText.textContent = 'Disconnected';
      portInfo.textContent = '';
    }
  }

  function log(text, cls = 'recv') {
    const div = document.createElement('div');
    div.className = 'line ' + cls;
    div.textContent = text;
    terminal.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
  }

  function logSystem(text) {
    log(text, 'system');
  }

  function logSent(text) {
    log('> ' + text, 'sent');
  }

  /* ---------- Serial ---------- */

  async function connect() {
    if (port) {
      await disconnect();
      return;
    }

    try {
      logSystem('Requesting port…');
      port = await navigator.serial.requestPort({
        filters: [
          // SAMD21 boards typically expose a CDC ACM port; vendor ids vary.
          // We accept any serial port the user picks.
        ],
      });

      await port.open({ baudRate: BAUD });

      // Text flow:  writer.write("CMD\n") -> enc (string->bytes) -> port.writable
      //             port.readable -> dec (bytes->string) -> reader.read()
      // Note: TextEncoderStream exposes enc.**writable** for writing text;
      // enc.readable is a byte stream and only has getReader().
      const enc = new TextEncoderStream();
      const dec = new TextDecoderStream();
      enc.readable.pipeTo(port.writable).catch(() => {});
      port.readable.pipeTo(dec.writable).catch(() => {});
      writer = enc.writable.getWriter();
      reader = dec.readable.getReader();

      const info = port.getInfo ? port.getInfo() : null;
      const label =
        info && info.usbVendorId != null
          ? 'VID ' + info.usbVendorId.toString(16).padStart(4, '0') +
            ':' + (info.usbProductId || 0).toString(16).padStart(4, '0')
          : 'serial';
      setConnected(true, label);
      logSystem('Connected at ' + BAUD + ' baud.');

      readLoopPromise = readLoop();
    } catch (err) {
      logSystem('Error: ' + err.message, 'error');
      port = null;
      setConnected(false);
    }
  }

  async function disconnect() {
    try {
      if (writer) {
        // Closing the encoder ends enc.readable, which closes port.writable.
        await writer.close();
        writer = null;
      }
      if (reader) {
        // Cancelling dec.readable errors dec.writable, which aborts the
        // port.readable -> dec.writable pipe and unlocks the port.
        await reader.cancel();
        reader = null;
      }
      if (port) {
        await port.close();
        port = null;
      }
    } catch (err) {
      logSystem('Disconnect error: ' + err.message, 'error');
    } finally {
      setConnected(false);
      logSystem('Disconnected.');
    }
  }

  function readLoop() {
    return new Promise((resolve) => {
      (function pump() {
        reader.read().then(({ value, done }) => {
          if (done) {
            resolve();
            return;
          }
          if (value) {
            buffer += value;
            let idx;
            while ((idx = buffer.indexOf('\n')) >= 0) {
              const line = buffer.slice(0, idx).replace(/\r$/, '');
              buffer = buffer.slice(idx + 1);
              if (line.length > 0) log(line);
            }
          }
          pump();
        }).catch((err) => {
          logSystem('Read error: ' + err.message, 'error');
          resolve();
        });
      })();
    });
  }

  async function send(text) {
    if (!writer) {
      logSystem('Not connected.', 'error');
      return;
    }
    try {
      const data = text + '\n';
      await writer.write(data);
      logSent(text);
    } catch (err) {
      logSystem('Send error: ' + err.message, 'error');
    }
  }

  /* ---------- Command wiring ---------- */

  connectBtn.addEventListener('click', connect);

  clearBtn.addEventListener('click', () => {
    terminal.innerHTML = '';
    logSystem('Log cleared.');
  });

  function fireCmd(cmd, targetId) {
    let payload = cmd;
    if (targetId) {
      const el = document.getElementById(targetId);
      if (el) {
        const v = el.value.trim();
        if (!v) {
          logSystem('Please enter a value.', 'error');
          return;
        }
        payload = cmd + ' ' + v;
      }
    }
    send(payload);
  }

  document.querySelectorAll('.cmd-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      fireCmd(btn.dataset.cmd, btn.dataset.target);
    });
  });

  document.querySelectorAll('.sign-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const network = btn.dataset.network;
      let inputId;
      if (network === 'BTC') inputId = 'btc-input';
      else if (network === 'BTCT') inputId = 'btct-input';
      else if (network === 'ETH') inputId = 'eth-input';

      const el = document.getElementById(inputId);
      const v = el.value.trim();
      if (!v) {
        logSystem('Please enter a hex value.', 'error');
        return;
      }
      // Basic hex validation
      if (!/^[0-9a-fA-F]+$/.test(v)) {
        logSystem('Invalid hex string.', 'error');
        return;
      }
      send(`SIGN ${network} ${v}`);
    });
  });

  // Enter key in text inputs triggers the associated button
  document.getElementById('name-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      fireCmd('NAME', 'name-input');
    }
  });
  document.getElementById('custom-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      fireCmd('CUSTOM', 'custom-input');
    }
  });
  ['btc-input', 'btct-input', 'eth-input'].forEach((id) => {
    document.getElementById(id).addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        const btn = document.querySelector(`.sign-btn[data-network="${id === 'btc-input' ? 'BTC' : id === 'btct-input' ? 'BTCT' : 'ETH'}"]`);
        if (btn) btn.click();
      }
    });
  });

  // Handle page unload
  window.addEventListener('beforeunload', () => {
    if (port) disconnect();
  });

  logSystem('Soteria debug client loaded. Click Connect to open a serial port.');
})();
