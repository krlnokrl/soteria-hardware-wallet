/* Soteria Wallet – Web Serial client for the JSON Lines protocol (v1) */

(function () {
  const BAUD = 115200;
  // Until a reply or a confirm_on_device event. Generous: some commands do
  // seconds of elliptic-curve math on the 48 MHz MCU before answering.
  const REPLY_TIMEOUT_MS = 20000;
  const USER_TIMEOUT_MS = 10 * 60000;   // once the device waits for the user

  const $ = (id) => document.getElementById(id);
  const connectBtn = $('connect-btn');
  const indicator = $('status-indicator');
  const statusText = $('status-text');
  const portInfo = $('port-info');
  const terminal = $('terminal');
  const banner = $('confirm-banner');
  const signOut = $('sign-out');

  let port = null;
  let writer = null;
  let reader = null;
  let buffer = '';
  let nextId = 1;
  let closing = false;
  let waitingForUser = false;
  let lastResult = '';
  const pending = new Map();   // id -> {resolve, reject, timer, cmd}

  // What the user has to do on the device, by command.
  const PROMPTS = {
    addresses: 'Allow reading the addresses',
    xpubs: 'Allow reading the xpubs',
    pubkeys: 'Allow reading the public keys',
    show_address: 'Compare the address on the screen',
    set_name: 'Confirm the new name',
    erase: 'Confirm twice, then enter the PIN (or PUK)',
    change_pin: 'Enter the current PIN, PUK and new PIN',
    sign_psbt: 'Review payments, fee and change, then enter the PIN',
    sign_btc: 'Review each output, then enter the PIN',
    sign_eth_tx: 'Review chain, recipient, value and fee, then enter the PIN',
    sign_eth_message: 'Review the message, then enter the PIN',
    sign_eth_hash: 'Blind signature: confirm, then enter the PIN',
  };

  /* ---------- UI helpers ---------- */

  // Status pill: disconnected / connecting / connected / busy / confirm / error.
  function setStatus(state, text) {
    indicator.dataset.state = state;
    statusText.textContent = text;
  }

  function updateStatus() {
    if (!port) return;
    if (waitingForUser) setStatus('confirm', 'Waiting for device');
    else if (pending.size) setStatus('busy', 'Working…');
    else setStatus('connected', 'Connected');
  }

  function setConnected(connected, portName = '') {
    connectBtn.textContent = connected ? 'Disconnect' : 'Connect';
    connectBtn.classList.toggle('connected', connected);
    if (connected) setStatus('connected', 'Connected');
    else setStatus('disconnected', 'Disconnected');
    portInfo.textContent = connected && portName ? portName : '';
    document.querySelectorAll('.needs-conn').forEach((b) => { b.disabled = !connected; });
    if (!connected) {
      $('device-info').innerHTML = '';
      showBanner(null);
    }
  }

  function log(text, cls = 'recv') {
    const div = document.createElement('div');
    div.className = 'line ' + cls;
    div.textContent = text;
    terminal.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
  }
  const logSystem = (text) => log(text, 'system');
  const logError = (text) => log(text, 'error');

  function toast(text, kind = 'info') {
    const div = document.createElement('div');
    div.className = 'toast ' + kind;
    const span = document.createElement('span');
    span.textContent = text;
    const close = document.createElement('button');
    close.textContent = '×';
    close.title = 'Dismiss';
    close.addEventListener('click', () => div.remove());
    div.append(span, close);
    $('toasts').appendChild(div);
    setTimeout(() => div.remove(), kind === 'error' ? 10000 : 4000);
  }

  function showBanner(cmd) {
    waitingForUser = !!cmd;
    banner.hidden = !cmd;
    $('confirm-what').textContent = cmd ? PROMPTS[cmd] || cmd : '';
    updateStatus();
  }

  function copyText(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
      if (!btn) return toast('Copied to clipboard.', 'ok');
      const label = btn.textContent;
      btn.textContent = 'Copied';
      btn.classList.add('done');
      setTimeout(() => { btn.textContent = label; btn.classList.remove('done'); }, 1500);
    }, () => toast('Clipboard not available.', 'error'));
  }

  // entries: [key, value, tone?] with tone 'ok' / 'warn' for a coloured dot
  function fillKv(dl, entries) {
    dl.innerHTML = '';
    for (const [k, v, tone] of entries) {
      const dt = document.createElement('dt');
      dt.textContent = k;
      const dd = document.createElement('dd');
      if (tone) {
        const dot = document.createElement('span');
        dot.className = 'tone ' + tone;
        dd.appendChild(dot);
      }
      dd.append(v);
      dl.append(dt, dd);
    }
  }

  // A labelled code block with a copy button.
  function codeField(label, value, meta) {
    const box = document.createElement('div');
    box.className = 'field';
    const head = document.createElement('div');
    head.className = 'field-head';
    const l = document.createElement('span');
    l.className = 'field-label';
    l.textContent = label;
    head.appendChild(l);
    if (meta) {
      const m = document.createElement('span');
      m.className = 'field-meta';
      m.textContent = meta;
      head.appendChild(m);
    }
    const btn = document.createElement('button');
    btn.className = 'copy';
    btn.textContent = 'Copy';
    btn.addEventListener('click', () => copyText(String(value), btn));
    head.appendChild(btn);
    const pre = document.createElement('pre');
    const code = document.createElement('code');
    code.textContent = String(value);
    pre.appendChild(code);
    box.append(head, pre);
    return box;
  }

  function groupTitle(text, badge, badgeClass = '') {
    const h = document.createElement('div');
    h.className = 'group-title';
    h.textContent = text;
    if (badge) {
      const b = document.createElement('span');
      b.className = 'badge ' + badgeClass;
      b.textContent = badge;
      h.appendChild(b);
    }
    return h;
  }

  // rows: [label, value, meta?] (skipped if value is missing) or a node such as a group title
  function fillFields(container, rows) {
    container.innerHTML = '';
    for (const r of rows) {
      if (r instanceof window.Node) container.appendChild(r);
      else if (r[1] != null) container.appendChild(codeField(r[0], r[1], r[2]));
    }
  }

  function callout(text, kind) {
    const p = document.createElement('p');
    p.className = 'callout callout-' + kind;
    p.textContent = text;
    return p;
  }

  // Sign results: an object becomes one code block per field, a string a message.
  function showResult(obj) {
    signOut.innerHTML = '';
    if (typeof obj === 'string') {
      lastResult = obj;
      signOut.appendChild(callout(obj, obj.startsWith('Error') ? 'error' : 'ok'));
      return;
    }
    lastResult = JSON.stringify(obj, null, 2);
    fillFields(signOut, Object.entries(obj).map(([k, v]) =>
      [k, typeof v === 'object' ? JSON.stringify(v, null, 2) : v]));
  }

  /* ---------- Tabs ---------- */

  function selectTab(tab) {
    for (const t of tab.parentElement.querySelectorAll('[role="tab"]')) {
      const selected = t === tab;
      t.setAttribute('aria-selected', selected);
      t.tabIndex = selected ? 0 : -1;
      $(t.getAttribute('aria-controls')).hidden = !selected;
    }
  }

  for (const list of document.querySelectorAll('[role="tablist"]')) {
    const tabs = [...list.querySelectorAll('[role="tab"]')];
    for (const t of tabs) {
      t.tabIndex = t.getAttribute('aria-selected') === 'true' ? 0 : -1;
      t.addEventListener('click', () => selectTab(t));
    }
    list.addEventListener('keydown', (e) => {   // arrow keys move between tabs
      const step = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
      const i = tabs.indexOf(document.activeElement);
      if (!step || i < 0) return;
      e.preventDefault();
      const next = tabs[(i + step + tabs.length) % tabs.length];
      selectTab(next);
      next.focus();
    });
  }

  /* ---------- Serial transport ---------- */

  async function connect() {
    if (port) {
      await disconnect();
      return;
    }
    try {
      // No vendor filter: Feather M0 builds use VID 0x239a, M0 Pro boards others.
      port = await navigator.serial.requestPort();
      setStatus('connecting', 'Connecting…');
      await port.open({ baudRate: BAUD });
      // The firmware only transmits while the host asserts DTR.
      await port.setSignals({ dataTerminalReady: true, requestToSend: true });

      const enc = new TextEncoderStream();
      const dec = new TextDecoderStream();
      enc.readable.pipeTo(port.writable).catch(() => {});
      port.readable.pipeTo(dec.writable).catch(() => {});
      writer = enc.writable.getWriter();
      reader = dec.readable.getReader();

      const info = port.getInfo();
      const label = info.usbVendorId != null
        ? 'VID ' + info.usbVendorId.toString(16).padStart(4, '0') +
          ':' + (info.usbProductId || 0).toString(16).padStart(4, '0')
        : 'serial';
      setConnected(true, label);
      logSystem('Connected.');
      readLoop();
      await refreshInfo();
    } catch (err) {
      logError('Error: ' + err.message);
      // Closing the port chooser is not an error worth a toast.
      if (err.name !== 'NotFoundError') toast('Connection failed: ' + err.message, 'error');
      port = null;
      setConnected(false);
    }
  }

  async function disconnect() {
    if (closing) return;
    closing = true;
    for (const [, p] of pending) {
      clearTimeout(p.timer);
      p.reject(new Error('disconnected'));
    }
    pending.clear();
    try {
      if (writer) { await writer.close(); writer = null; }
      if (reader) { await reader.cancel(); reader = null; }
      if (port) { await port.close(); port = null; }
    } catch (err) {
      logError('Disconnect error: ' + err.message);
    } finally {
      port = null;
      writer = reader = null;
      closing = false;
      setConnected(false);
      logSystem('Disconnected.');
    }
  }

  async function readLoop() {
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += value;
        let idx;
        while ((idx = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, idx).replace(/\r$/, '');
          buffer = buffer.slice(idx + 1);
          if (line.length > 0) handleLine(line);
        }
      }
    } catch (err) {
      if (port && !closing) logError('Read error: ' + err.message);
    }
    // The stream ended without Disconnect being clicked: device unplugged or reset.
    if (port && !closing) {
      toast('Device disconnected.', 'error');
      await disconnect();
    }
  }

  function handleLine(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch (e) {
      log(line);   // not JSON: show as-is
      return;
    }
    if (msg.event) {
      log('← ' + line, 'event');
      const p = pending.get(msg.id);
      if (msg.event === 'confirm_on_device') {
        showBanner(msg.cmd || 'request');
        if (p) {   // the user may take a while: switch to the long timeout
          clearTimeout(p.timer);
          p.timer = setTimeout(() => expire(msg.id), USER_TIMEOUT_MS);
        }
      }
      return;
    }
    log('← ' + line, msg.ok === false ? 'error' : 'recv');
    const p = pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    clearTimeout(p.timer);
    showBanner(null);
    if (msg.ok) {
      p.resolve(msg.result);
    } else {
      const e = new Error((msg.error && msg.error.msg) || 'device error');
      e.code = msg.error && msg.error.code;
      p.reject(e);
    }
  }

  function expire(id) {
    const p = pending.get(id);
    if (!p) return;
    pending.delete(id);
    showBanner(null);
    const e = new Error('no reply from device');
    e.code = 'TIMEOUT';
    p.reject(e);
  }

  async function sendLine(text) {
    if (!writer) throw new Error('not connected');
    await writer.write(text + '\n');
    log('→ ' + text, 'sent');
  }

  // Send {id, cmd, ...params}; resolves with `result` or rejects with
  // an Error carrying the device's error code.
  function request(cmd, params = {}) {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => expire(id), REPLY_TIMEOUT_MS);
      pending.set(id, { resolve, reject, timer, cmd });
      updateStatus();
      sendLine(JSON.stringify({ id, cmd, ...params })).catch((err) => {
        pending.delete(id);
        clearTimeout(timer);
        updateStatus();
        reject(err);
      });
    });
  }

  // Run a request from a button: disable it meanwhile, report failures.
  // Buttons marked data-manual (sign / broadcast steps) stay disabled after
  // success - the step is done - and are re-enabled only to retry an error.
  async function run(btn, fn) {
    btn.disabled = true;
    let ok = false;
    try {
      await fn();
      ok = true;
    } catch (err) {
      const text = (err.code ? err.code + ': ' : '') + err.message;
      logError(text);
      toast(text, 'error');
      if (btn.closest('#panel-sign')) showResult('Error – ' + text);
    } finally {
      if (!('manual' in btn.dataset)) btn.disabled = btn.classList.contains('needs-conn') && !port;
      else if (!ok) btn.disabled = false;
    }
  }

  /* ---------- Input helpers ---------- */

  function hexInput(id, what) {
    let v = $(id).value.trim().replace(/\s+/g, '');
    if (v.startsWith('0x') || v.startsWith('0X')) v = v.slice(2);
    if (!v) throw new Error('enter ' + what);
    if (!/^[0-9a-fA-F]+$/.test(v) || v.length % 2) throw new Error(what + ' must be even-length hex');
    return v.toLowerCase();
  }

  const PSBT_MAGIC = [0x70, 0x73, 0x62, 0x74, 0xff];   // "psbt" 0xff

  function bytesToBase64(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  }

  // A PSBT pasted as base64 ("cHNidP8...") or hex ("70736274ff..."). A raw
  // transaction is a common mix-up when copying from a wallet: it lacks the
  // input amounts and key paths a signer needs, so say what to export instead.
  function psbtFromText(text, what) {
    const t = text.trim().replace(/\s+/g, '').replace(/^0x/i, '');
    if (!t) throw new Error('paste ' + what + ' or load a .psbt file');
    if (/^70736274ff[0-9a-f]*$/i.test(t) && t.length % 2 === 0) return C.hexToBytes(t);
    if (/^0[12]000000[0-9a-f]*$/i.test(t)) {
      throw new Error('this is a raw transaction, not a PSBT: it lacks the input amounts and key paths the ' +
        'device needs. In Sparrow: Finalize Transaction for Signing, then export the PSBT (Save Transaction ' +
        'gives a .psbt file; or copy it as Base64) and paste or load that here.');
    }
    if (!t.startsWith('cHNidP8') || !/^[A-Za-z0-9+/]+={0,2}$/.test(t)) {
      throw new Error('not a PSBT: expected base64 starting with "cHNidP8" or hex starting with "70736274ff"');
    }
    return Uint8Array.from(atob(t), (c) => c.charCodeAt(0));
  }

  // Load a .psbt file (binary, or base64/hex text) into a textarea as base64.
  async function loadPsbtFile(file, textarea) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const binary = PSBT_MAGIC.every((b, i) => bytes[i] === b);
    textarea.value = binary ? bytesToBase64(bytes)
      : bytesToBase64(psbtFromText(new TextDecoder().decode(bytes), 'a PSBT'));
    textarea.dispatchEvent(new Event('input'));
  }

  /* ---------- Commands ---------- */

  async function refreshInfo() {
    const r = await request('info');
    const se = r.secure_element && r.secure_element.ready;
    fillKv($('device-info'), [
      ['Firmware', r.fw + ' (protocol ' + r.proto + ')'],
      ['Wallet', r.wallet ? (r.name ? '"' + r.name + '"' : 'unnamed') : 'none – generate on device',
        r.wallet ? 'ok' : 'warn'],
      ['FIDO2', !r.fido.supported ? 'not in this build'
        : r.fido.ready ? 'ready, counter ' + r.fido.counter : 'no wallet yet',
        r.fido.supported && r.fido.ready ? 'ok' : undefined],
      ['Secure element', se ? 'ATECC508A ' + r.secure_element.serial : 'not ready (provision with env:seprov)',
        se ? 'ok' : 'warn'],
      ['Host access', r.host_access ? 'granted' : 'not yet granted', r.host_access ? 'ok' : undefined],
      ['Max payload', r.limits.max_payload + ' bytes, ' + r.limits.free_ram + ' bytes RAM free'],
    ]);
  }

  $('info-btn').addEventListener('click', (e) => run(e.target, refreshInfo));

  $('addresses-btn').addEventListener('click', (e) => run(e.target, async () => {
    const r = await request('addresses');
    fillFields($('addr-out'), [
      groupTitle('Bitcoin', 'mainnet', 'badge-btc'),
      ['Native SegWit', r.btc, 'm/84\'/0\'/0\'/0/0'],
      ['Legacy', r.btc_legacy, 'm/44\'/0\'/0\'/0/0'],
      groupTitle('Bitcoin', 'testnet', 'badge-test'),
      ['Native SegWit', r.btc_testnet, 'm/84\'/1\'/0\'/0/0'],
      ['Legacy', r.btc_testnet_legacy, 'm/44\'/1\'/0\'/0/0'],
      groupTitle('Ethereum / EVM', 'all chains', 'badge-eth'),
      ['Address', r.eth, 'm/44\'/60\'/0\'/0/0'],
    ]);
    if (!$('evm-from').value) $('evm-from').value = r.eth;
  }));

  $('xpubs-btn').addEventListener('click', (e) => run(e.target, async () => {
    const r = await request('xpubs');
    fillFields($('xpub-out'), [
      ['Master fingerprint', r.fingerprint],
      groupTitle('Bitcoin', 'mainnet', 'badge-btc'),
      ['xpub', r.btc.xpub, r.btc.path],
      ['Receive descriptor', r.btc.receive],
      ['Change descriptor', r.btc.change],
      groupTitle('Bitcoin', 'testnet', 'badge-test'),
      ['tpub', r.btc_testnet.xpub, r.btc_testnet.path],
      ['Receive descriptor', r.btc_testnet.receive],
      ['Change descriptor', r.btc_testnet.change],
    ]);
  }));

  $('verify-btn').addEventListener('click', (e) => run(e.target, async () => {
    const index = parseInt($('verify-index').value, 10) || 0;
    const r = await request('show_address', {
      coin: $('verify-coin').value,
      index,
      change: $('verify-change').checked ? 1 : 0,
    });
    fillFields($('verify-out'), [
      ['Address', r.address, $('verify-coin').selectedOptions[0].textContent + ' #' + index],
      r.confirmed ? callout('You confirmed on the device that it matches.', 'ok')
        : callout('You reported a MISMATCH on the device – do not use this address.', 'error'),
    ]);
  }));

  $('pubkeys-btn').addEventListener('click', (e) => run(e.target, async () => {
    const r = await request('pubkeys');
    fillFields($('pubkey-out'), [
      ['Bitcoin', r.btc, '33-byte compressed'],
      ['Bitcoin testnet', r.btc_testnet, '33-byte compressed'],
      ['Ethereum / EVM', r.eth, '65-byte uncompressed'],
    ]);
  }));

  $('name-btn').addEventListener('click', (e) => run(e.target, async () => {
    const name = $('name-input').value.trim();
    if (!/^[\x21-\x7e]{1,8}$/.test(name)) throw new Error('name: 1-8 printable characters, no spaces');
    await request('set_name', { name });
    await refreshInfo();
  }));

  $('pin-btn').addEventListener('click', (e) => run(e.target, async () => {
    await request('change_pin');   // current PIN, PUK and new PIN on the device
  }));

  $('erase-btn').addEventListener('click', (e) => run(e.target, async () => {
    if (!confirm('Erase the wallet? Funds are only recoverable with the 12 backup words, ' +
                 'and FIDO2 registrations made with this wallet stop working. ' +
                 'The device asks for the PIN (or the PUK for a factory reset).')) return;
    await request('erase');
    for (const id of ['addr-out', 'xpub-out', 'pubkey-out', 'verify-out']) $(id).innerHTML = '';
    await refreshInfo();
  }));

  $('ethtx-btn').addEventListener('click', (e) => run(e.target, async () => {
    const r = await request('sign_eth_tx', { tx: hexInput('ethtx-input', 'transaction') });
    const out = { chain: (r.chain_name || 'unknown chain') + ' (' + r.chain + ')' };
    if (r.erc20) out.erc20 = r.erc20;
    Object.assign(out, { signed_tx: '0x' + r.tx, r: r.r, s: r.s, recid: r.recid });
    showResult(out);
  }));

  $('psbt-btn').addEventListener('click', (e) => run(e.target, async () => {
    const psbt = bytesToBase64(psbtFromText($('psbt-input').value, 'the unsigned PSBT'));
    const r = await request('sign_psbt', { psbt, testnet: $('psbt-testnet').checked });
    const btc = (sats) => (sats / 1e8).toFixed(8);
    $('btc-signed').value = r.psbt;   // ready for "Finalize & broadcast"
    $('btc-net').value = $('psbt-testnet').checked ? 'testnet4' : 'mainnet';
    showResult({
      signed_psbt: r.psbt,
      signed_inputs: r.signed_inputs,
      send: btc(r.send), fee: btc(r.fee), change: btc(r.change),
    });
    toast('Signed. To broadcast it, open Build & send → Bitcoin (already filled in).', 'ok');
  }));

  $('ethmsg-btn').addEventListener('click', (e) => run(e.target, async () => {
    const message = $('ethmsg-input').value;
    if (!message) throw new Error('enter a message');
    const r = await request('sign_eth_message', { message });
    showResult({ signature: '0x' + r.signature, r: r.r, s: r.s, v: r.v });
  }));

  $('btc-btn').addEventListener('click', (e) => run(e.target, async () => {
    const r = await request('sign_btc', {
      tx: hexInput('btc-input', 'transaction'),
      testnet: $('btc-testnet').checked,
    });
    showResult({ signed_tx: r.tx });
  }));

  $('ethhash-btn').addEventListener('click', (e) => run(e.target, async () => {
    const hash = hexInput('ethhash-input', 'hash');
    if (hash.length !== 64) throw new Error('hash must be 32 bytes (64 hex chars)');
    const r = await request('sign_eth_hash', { hash });
    showResult({ signature: '0x' + r.signature, r: r.r, s: r.s, v: r.v, recid: r.recid });
  }));

  /* ---------- Build & send ---------- */

  const C = window.SoteriaChain;
  const evm = { tx: null, signed: null, token: null };
  const btcState = { hex: null };

  function link(href, text) {
    const a = document.createElement('a');
    a.href = href;
    a.textContent = text;
    a.target = '_blank';
    a.rel = 'noopener';
    return a;
  }

  function evmNetwork() {
    return C.EVM_NETWORKS[$('evm-net').selectedIndex];
  }

  function evmReset() {
    evm.tx = evm.signed = null;
    $('evm-sign').disabled = true;
    $('evm-send').disabled = true;
  }

  function evmUnit() {
    $('evm-unit').textContent = evm.token ? evm.token.symbol : evmNetwork().symbol;
  }

  for (const n of C.EVM_NETWORKS) {
    const o = document.createElement('option');
    o.textContent = n.name + ' (' + n.id + ')';
    $('evm-net').appendChild(o);
  }
  $('evm-net').addEventListener('change', () => {
    $('evm-rpc').value = evmNetwork().rpc;
    evm.token = null;
    evmUnit();
    evmReset();
  });
  $('evm-rpc').value = evmNetwork().rpc;
  evmUnit();
  ['evm-from', 'evm-to', 'evm-amount', 'evm-rpc'].forEach((id) => $(id).addEventListener('input', evmReset));
  $('evm-token').addEventListener('input', () => { evm.token = null; evmUnit(); evmReset(); });

  $('evm-from-btn').addEventListener('click', (e) => run(e.target, async () => {
    const r = await request('addresses');
    $('evm-from').value = r.eth;
    evmReset();
  }));

  $('evm-token-btn').addEventListener('click', (e) => run(e.target, async () => {
    const addr = $('evm-token').value.trim();
    evm.token = { address: addr, ...(await C.readToken($('evm-rpc').value.trim(), addr)) };
    evmUnit();
    $('evm-out').textContent = 'Token ' + evm.token.symbol + ', ' + evm.token.decimals + ' decimals';
  }));

  $('evm-prepare').addEventListener('click', (e) => run(e.target, async () => {
    evmReset();
    const net = evmNetwork();
    const tokenAddr = $('evm-token').value.trim();
    if (tokenAddr && !evm.token) throw new Error('look up the token first (its decimals are needed)');
    const decimals = evm.token ? evm.token.decimals : 18;
    const amount = C.parseUnits($('evm-amount').value, decimals);
    const unit = evm.token ? evm.token.symbol : net.symbol;
    const tx = await C.prepareEthTx({
      rpcUrl: $('evm-rpc').value.trim(), chainId: net.id,
      from: $('evm-from').value.trim(), to: $('evm-to').value.trim(),
      value: evm.token ? 0n : amount, token: evm.token ? evm.token.address : null, amount,
    });
    evm.tx = tx;
    const gwei = (w) => C.formatUnits(w, 9) + ' gwei';
    $('evm-out').textContent = [
      'Network:   ' + net.name + ' (chain ' + net.id + ')',
      'Send:      ' + C.formatUnits(amount, decimals) + ' ' + unit + ' to ' + $('evm-to').value.trim(),
      evm.token ? 'Token:     ' + evm.token.address : null,
      'Nonce:     ' + tx.nonce + ',  gas limit ' + tx.gas,
      tx.type === 2 ? 'Max fee:   ' + gwei(tx.maxFeePerGas) + ' (tip ' + gwei(tx.maxPriorityFeePerGas) + ')'
        : 'Gas price: ' + gwei(tx.gasPrice),
      'Max cost:  ' + C.formatUnits(tx.maxCost, 18) + ' ' + net.symbol + ' in fees',
      '',
      'Unsigned:  0x' + tx.unsignedHex,
    ].filter((l) => l !== null).join('\n');
    $('evm-sign').disabled = !port;
  }));

  $('evm-sign').addEventListener('click', (e) => run(e.target, async () => {
    if (!evm.tx) throw new Error('prepare the transaction first');
    const r = await request('sign_eth_tx', { tx: evm.tx.unsignedHex });
    evm.signed = '0x' + r.tx;
    $('evm-out').textContent += '\n\nSigned:    ' + evm.signed;
    $('evm-send').disabled = false;
  }));

  $('evm-send').addEventListener('click', (e) => run(e.target, async () => {
    const net = evmNetwork();
    if (!evm.signed) throw new Error('sign the transaction first');
    if (!confirm('Broadcast this transaction on ' + net.name + '? This cannot be undone.')) {
      e.target.disabled = false;   // cancelled: the step is still open
      return;
    }
    const hash = await C.broadcastEthTx($('evm-rpc').value.trim(), evm.signed);
    $('evm-out').textContent += '\n\nBroadcast: ' + hash + '\n';
    $('evm-out').appendChild(link(net.explorer + '/tx/' + hash, 'View on explorer'));
    $('evm-send').disabled = true;
  }));

  $('btc-signed').addEventListener('input', () => { btcState.hex = null; $('btc-send').disabled = true; });
  $('btc-net').addEventListener('change', () => { btcState.hex = null; $('btc-send').disabled = true; });

  $('btc-finalize').addEventListener('click', (e) => run(e.target, async () => {
    btcState.hex = null;
    $('btc-send').disabled = true;
    const bytes = psbtFromText($('btc-signed').value, 'the signed PSBT');
    const r = await C.finalizePsbt(bytes, $('btc-net').value);
    btcState.hex = r.hex;
    const btc = (sats) => C.formatUnits(sats, 8) + ' BTC';
    $('btc-out').textContent = [
      ...r.outputs.map((o, i) => 'Output ' + (i + 1) + ': ' + btc(o.value) + '  ' + o.address),
      'Fee:      ' + btc(r.fee) + '  (' + (Number(r.fee) / r.vsize).toFixed(1) + ' sat/vB, ' + r.vsize + ' vB)',
      'Txid:     ' + r.txid,
      '',
      'Raw tx:   ' + r.hex,
    ].join('\n');
    $('btc-send').disabled = false;
  }));

  $('btc-send').addEventListener('click', (e) => run(e.target, async () => {
    const net = C.BTC_NETWORKS[$('btc-net').value];
    if (!btcState.hex) throw new Error('finalize first');
    if (!confirm('Broadcast this transaction on ' + net.name + '? This cannot be undone.')) {
      e.target.disabled = false;   // cancelled: the step is still open
      return;
    }
    const txid = await C.broadcastBtcTx($('btc-net').value, btcState.hex);
    $('btc-out').textContent += '\n\nBroadcast: ' + txid + '\n';
    $('btc-out').appendChild(link(net.web + '/tx/' + txid, 'View on mempool.space'));
    $('btc-send').disabled = true;
  }));

  for (const [inputId, areaId] of [['psbt-file', 'psbt-input'], ['btc-file', 'btc-signed']]) {
    $(inputId).addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;
      loadPsbtFile(file, $(areaId)).catch((err) => {
        logError(err.message);
        toast(err.message, 'error');
      });
      e.target.value = '';   // allow loading the same file again
    });
  }

  // Raw console: JSON objects get an id (if missing) and go through
  // request() so replies are matched; anything else is sent verbatim.
  async function sendRaw() {
    const text = $('raw-input').value.trim();
    if (!text) return;
    if (text.startsWith('{')) {
      let obj;
      try {
        obj = JSON.parse(text);
      } catch (err) {
        throw new Error('invalid JSON: ' + err.message);
      }
      const { cmd, ...params } = obj;
      delete params.id;
      await request(cmd, params);   // the reply is shown in the log
    } else {
      await sendLine(text);
    }
  }
  $('raw-btn').addEventListener('click', (e) => run(e.target, sendRaw));
  $('raw-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      run($('raw-btn'), sendRaw);
    }
  });
  $('name-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      $('name-btn').click();
    }
  });

  $('copy-btn').addEventListener('click', () => {
    if (lastResult) copyText(lastResult);
  });

  $('clear-btn').addEventListener('click', () => {
    terminal.innerHTML = '';
    logSystem('Log cleared.');
  });

  connectBtn.addEventListener('click', connect);
  window.addEventListener('beforeunload', () => {
    if (port) disconnect();
  });

  setConnected(false);
  if (!('serial' in navigator)) {
    logError('This browser has no Web Serial support – use Chrome or Edge.');
    toast('This browser has no Web Serial support – use Chrome or Edge.', 'error');
    setStatus('error', 'No Web Serial');
    connectBtn.disabled = true;
  } else {
    logSystem('Click Connect and choose the Soteria serial port.');
  }
})();
