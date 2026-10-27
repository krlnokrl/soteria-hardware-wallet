// The page (index.html + chain.js + app.js) in jsdom against a simulated
// device speaking the JSON-lines protocol, a mocked RPC node and mempool.space.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { webcrypto } = require('node:crypto');
const { JSDOM } = require('jsdom');
const fx = require('./fixtures.json');

const WEB = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(WEB, f), 'utf8');
const tick = (ms = 50) => new Promise((r) => setTimeout(r, ms));

/* ---------- simulated device ---------- */
const received = [];   // request lines the device got
class FakePort {
  constructor() {
    this.readable = new ReadableStream({ start: (c) => { this.ctrl = c; } });
    let buf = '';
    this.writable = new WritableStream({
      write: (chunk) => {
        buf += typeof chunk === 'string' ? chunk : new TextDecoder().decode(chunk);
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          this.onLine(buf.slice(0, i));
          buf = buf.slice(i + 1);
        }
      },
    });
  }
  async open() {}
  async setSignals(s) { this.signals = s; }
  async close() {}
  getInfo() { return { usbVendorId: 0x239a, usbProductId: 0x800b }; }
  emit(obj) { this.ctrl.enqueue(new TextEncoder().encode(JSON.stringify(obj) + '\n')); }
  onLine(line) {
    received.push(line);
    const req = JSON.parse(line);
    const ok = (result) => this.emit({ id: req.id, ok: true, result });
    const confirmed = (result) => {   // device waits for a button press first
      this.emit({ event: 'confirm_on_device', id: req.id, cmd: req.cmd });
      setTimeout(() => ok(result), 100);
    };
    switch (req.cmd) {
      case 'info': return ok({ fw: '0.4.0', proto: 1, wallet: true, name: 'test', segwit: true, host_access: false,
                               fido: { supported: true, ready: true, counter: 3 },
                               limits: { max_line: 3072, max_payload: 2048, free_ram: 9000 } });
      case 'addresses': return confirmed({ btc: 'bc1qtest', btc_testnet: 'tb1qtest', btc_legacy: '1Test',
                                           btc_testnet_legacy: 'mTest', eth: '0x' + '11'.repeat(20) });
      case 'sign_eth_tx': return confirmed({ tx: 'f00d' + req.tx, r: 'aa', s: 'bb', recid: 0, chain: 11155111 });
      case 'sign_psbt': return confirmed({ psbt: fx.btc[1].psbt, signed_inputs: 2, fee: 1000, send: 2, change: 3 });
      default: return this.emit({ id: req.id, ok: false, error: { code: 'UNKNOWN_CMD', msg: 'unknown' } });
    }
  }
}

/* ---------- page ---------- */
const html = read('index.html').replace(/<script[^>]*><\/script>/g, '');
const dom = new JSDOM(html, { runScripts: 'outside-only' });
const w = dom.window;
const $ = (id) => w.document.getElementById(id);
const port = new FakePort();
const net = [];   // requests to the RPC node / mempool.space
Object.assign(w, { TextEncoderStream, TextDecoderStream, ReadableStream, WritableStream, TextDecoder, TextEncoder });
Object.defineProperty(w, 'crypto', { value: webcrypto, configurable: true });
w.navigator.serial = { requestPort: async () => port };
w.confirm = () => true;
w.fetch = async (url, opts) => {
  net.push({ url, body: opts.body });
  if (url.includes('mempool.space')) return { ok: true, text: async () => fx.btc[1].txid };
  const req = JSON.parse(opts.body);
  const results = { eth_chainId: '0xaa36a7', eth_getTransactionCount: '0x3', eth_estimateGas: '0x5208',
    eth_getBlockByNumber: { baseFeePerGas: '0x3b9aca00' }, eth_maxPriorityFeePerGas: '0x77359400',
    eth_sendRawTransaction: '0x' + 'ab'.repeat(32) };
  return { ok: true, json: async () => ({ jsonrpc: '2.0', id: req.id, result: results[req.method] }) };
};
w.eval(read('chain.js'));
w.eval(read('app.js'));
const lastRequest = (cmd) => received.map((l) => JSON.parse(l)).filter((r) => r.cmd === cmd).pop();

test('connect: DTR asserted, device info shown', async () => {
  $('connect-btn').click();
  await tick(150);
  assert.strictEqual($('status-text').textContent, 'Connected');
  assert.strictEqual(port.signals.dataTerminalReady, true);
  assert.match($('device-info').textContent, /0\.4\.0/);
});

test('request waiting for the device shows the confirm banner, then the result', async () => {
  $('addresses-btn').click();
  await tick(60);
  assert.strictEqual($('confirm-banner').hidden, false);
  await tick(200);
  assert.strictEqual($('confirm-banner').hidden, true);
  assert.match($('wallet-out').textContent, /bc1qtest/);
});

test('Ethereum: prepare, sign the exact transaction on the device, broadcast', async () => {
  $('evm-net').selectedIndex = 1;   // Sepolia
  $('evm-net').dispatchEvent(new w.Event('change'));
  $('evm-from').value = '0x' + '11'.repeat(20);
  $('evm-to').value = '0x' + '22'.repeat(20);
  $('evm-amount').value = '0.5';
  $('evm-prepare').click();
  await tick(150);
  const unsigned = /Unsigned:  0x([0-9a-f]+)/.exec($('evm-out').textContent)[1];
  $('evm-sign').click();
  await tick(300);
  assert.strictEqual(lastRequest('sign_eth_tx').tx, unsigned);
  $('evm-send').click();
  await tick(150);
  const sent = net.find((n) => (n.body || '').includes('eth_sendRawTransaction'));
  assert.strictEqual(JSON.parse(sent.body).params[0], '0xf00d' + unsigned);
  assert.strictEqual($('evm-out').querySelector('a').href, 'https://sepolia.etherscan.io/tx/0x' + 'ab'.repeat(32));
});

test('Bitcoin: raw transaction refused with an explanation, PSBT signed, finalized, broadcast', async () => {
  const before = received.length;
  $('psbt-input').value = '02000000013a0b13f94a2a414805f1fd370befb7a751a9481d13a1ba2d2b0b7c96adad9cb70100000000fdffffff01a24e0300000000001600142ca3d92cf47f88998dfd9a3cf0f76346f603918000000000';
  $('psbt-btn').click();
  await tick(60);
  assert.match($('sign-out').textContent, /raw transaction, not a PSBT/);
  assert.strictEqual(received.length, before);   // nothing sent to the device

  $('psbt-input').value = Buffer.from(fx.btc[1].unsigned, 'base64').toString('hex');   // hex accepted too
  $('psbt-testnet').checked = true;
  $('psbt-btn').click();
  await tick(300);
  assert.strictEqual(lastRequest('sign_psbt').psbt, fx.btc[1].unsigned);
  assert.strictEqual(lastRequest('sign_psbt').testnet, true);

  $('btc-finalize').click();   // signed PSBT and network were filled in
  await tick(150);
  assert.ok($('btc-out').textContent.includes(fx.btc[1].txid));
  $('btc-send').click();
  await tick(150);
  const push = net.find((n) => n.url.includes('mempool.space'));
  assert.strictEqual(push.url, 'https://mempool.space/testnet4/api/tx');
  assert.strictEqual(push.body, fx.btc[1].hex);
});
