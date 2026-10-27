/* Soteria Wallet – helpers to build and publish transactions (no dependencies).
 *
 * Ethereum / EVM: query a JSON-RPC node for nonce, fees and gas, encode the
 * unsigned transaction (RLP) for the device to sign, broadcast the signed one.
 * Bitcoin: finalize a PSBT signed by the device (native SegWit inputs) into
 * a raw transaction and broadcast it through a mempool.space-style API.
 *
 * Loaded by index.html (window.SoteriaChain) and by Node for tests.
 */
(function (exports) {
  'use strict';

  /* ---------- bytes ---------- */

  function hexToBytes(hex) {
    let h = hex.trim();
    if (h.startsWith('0x') || h.startsWith('0X')) h = h.slice(2);
    if (h.length % 2 || /[^0-9a-fA-F]/.test(h)) throw new Error('invalid hex');
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(2 * i, 2), 16);
    return out;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  function concat(...parts) {
    const len = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(len);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  // Minimal big-endian bytes of a non-negative BigInt (0 -> empty).
  function bigToBytes(n) {
    if (n < 0n) throw new Error('negative');
    let hex = n.toString(16);
    if (n === 0n) return new Uint8Array(0);
    if (hex.length % 2) hex = '0' + hex;
    return hexToBytes(hex);
  }

  /* ---------- decimal units ---------- */

  // "1.5" with 18 decimals -> 1500000000000000000n; rejects excess precision.
  function parseUnits(text, decimals) {
    const t = String(text).trim();
    const m = /^(\d*)(?:\.(\d*))?$/.exec(t);
    if (!m || t === '' || t === '.') throw new Error('invalid amount: ' + text);
    const frac = m[2] || '';
    if (frac.length > decimals) throw new Error('at most ' + decimals + ' decimals');
    return BigInt((m[1] || '0') + frac.padEnd(decimals, '0'));
  }

  function formatUnits(value, decimals) {
    const s = BigInt(value).toString().padStart(decimals + 1, '0');
    const int = s.slice(0, s.length - decimals);
    const frac = s.slice(s.length - decimals).replace(/0+$/, '');
    return frac ? int + '.' + frac : int;
  }

  /* ---------- RLP ---------- */

  function rlpLength(len, offset) {
    if (len <= 55) return Uint8Array.of(offset + len);
    const lb = bigToBytes(BigInt(len));
    return concat(Uint8Array.of(offset + 55 + lb.length), lb);
  }

  // item: Uint8Array (byte string) or Array of items (list)
  function rlpEncode(item) {
    if (Array.isArray(item)) {
      const payload = concat(...item.map(rlpEncode));
      return concat(rlpLength(payload.length, 0xc0), payload);
    }
    if (item.length === 1 && item[0] < 0x80) return item;
    return concat(rlpLength(item.length, 0x80), item);
  }

  /* ---------- Ethereum ---------- */

  // Public endpoints (publicnode.com) - checked to answer with the right
  // chain id and to allow browser (CORS) access. Any RPC URL can be used.
  const EVM_NETWORKS = [
    { id: 1, name: 'Ethereum', symbol: 'ETH', rpc: 'https://ethereum-rpc.publicnode.com', explorer: 'https://etherscan.io' },
    { id: 11155111, name: 'Sepolia (testnet)', symbol: 'ETH', rpc: 'https://ethereum-sepolia-rpc.publicnode.com', explorer: 'https://sepolia.etherscan.io' },
    { id: 560048, name: 'Hoodi (testnet)', symbol: 'ETH', rpc: 'https://ethereum-hoodi-rpc.publicnode.com', explorer: 'https://hoodi.etherscan.io' },
    { id: 137, name: 'Polygon', symbol: 'POL', rpc: 'https://polygon-bor-rpc.publicnode.com', explorer: 'https://polygonscan.com' },
    { id: 80002, name: 'Polygon Amoy (testnet)', symbol: 'POL', rpc: 'https://polygon-amoy-bor-rpc.publicnode.com', explorer: 'https://amoy.polygonscan.com' },
    { id: 56, name: 'BNB Chain', symbol: 'BNB', rpc: 'https://bsc-rpc.publicnode.com', explorer: 'https://bscscan.com' },
    { id: 97, name: 'BNB Chain testnet', symbol: 'tBNB', rpc: 'https://bsc-testnet-rpc.publicnode.com', explorer: 'https://testnet.bscscan.com' },
    { id: 8453, name: 'Base', symbol: 'ETH', rpc: 'https://base-rpc.publicnode.com', explorer: 'https://basescan.org' },
    { id: 84532, name: 'Base Sepolia (testnet)', symbol: 'ETH', rpc: 'https://base-sepolia-rpc.publicnode.com', explorer: 'https://sepolia.basescan.org' },
    { id: 42161, name: 'Arbitrum One', symbol: 'ETH', rpc: 'https://arbitrum-one-rpc.publicnode.com', explorer: 'https://arbiscan.io' },
    { id: 10, name: 'Optimism', symbol: 'ETH', rpc: 'https://optimism-rpc.publicnode.com', explorer: 'https://optimistic.etherscan.io' },
    { id: 43114, name: 'Avalanche C-Chain', symbol: 'AVAX', rpc: 'https://avalanche-c-chain-rpc.publicnode.com', explorer: 'https://snowtrace.io' },
  ];

  let rpcId = 1;
  async function rpc(url, method, params = []) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: rpcId++, method, params }),
    });
    if (!res.ok) throw new Error(method + ': HTTP ' + res.status);
    const body = await res.json();
    if (body.error) throw new Error(method + ': ' + (body.error.message || JSON.stringify(body.error)));
    return body.result;
  }

  const qty = (n) => '0x' + BigInt(n).toString(16);

  function checkAddress(a, what) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(a)) throw new Error(what + ': expected 0x followed by 40 hex characters');
    return a;
  }

  // ERC-20 transfer(to, amount) calldata.
  function erc20TransferData(to, amount) {
    const word = (b) => concat(new Uint8Array(32 - b.length), b);
    return concat(hexToBytes('a9059cbb'), word(hexToBytes(checkAddress(to, 'recipient'))), word(bigToBytes(amount)));
  }

  // symbol() and decimals() of a token contract (string or bytes32 symbol).
  async function readToken(rpcUrl, token) {
    checkAddress(token, 'token contract');
    const call = (sel) => rpc(rpcUrl, 'eth_call', [{ to: token, data: sel }, 'latest']);
    const dec = await call('0x313ce567');
    const symHex = (await call('0x95d89b41')).slice(2);
    let symbol;
    if (symHex.length > 128) {   // ABI string: offset, length, data
      const len = parseInt(symHex.slice(64, 128), 16);
      symbol = new TextDecoder().decode(hexToBytes(symHex.slice(128, 128 + 2 * len)));
    } else {                     // bytes32
      symbol = new TextDecoder().decode(hexToBytes(symHex)).replace(/\0+$/, '');
    }
    if (!dec || dec === '0x') throw new Error('not an ERC-20 token (no decimals())');
    return { symbol, decimals: Number(BigInt(dec)) };
  }

  // Unsigned EIP-1559 (or EIP-155 legacy) serialization, as the device expects it.
  function encodeEthTx(t) {
    const n = (v) => bigToBytes(BigInt(v));
    const to = hexToBytes(t.to);
    const data = t.data || new Uint8Array(0);
    if (t.type === 2) {
      return concat(Uint8Array.of(2), rlpEncode([n(t.chainId), n(t.nonce), n(t.maxPriorityFeePerGas),
        n(t.maxFeePerGas), n(t.gas), to, n(t.value), data, []]));
    }
    return rlpEncode([n(t.nonce), n(t.gasPrice), n(t.gas), to, n(t.value), data, n(t.chainId), n(0), n(0)]);
  }

  // Fill nonce, fees and gas from the node and return the transaction.
  // value is in wei; for tokens pass token + amount (base units) instead.
  async function prepareEthTx({ rpcUrl, chainId, from, to, value = 0n, token = null, amount = 0n }) {
    checkAddress(from, 'from');
    checkAddress(to, 'to');
    const nodeChain = Number(BigInt(await rpc(rpcUrl, 'eth_chainId')));
    if (nodeChain !== chainId) throw new Error('RPC node is on chain ' + nodeChain + ', expected ' + chainId);
    const target = token ? checkAddress(token, 'token contract') : to;
    const data = token ? erc20TransferData(to, amount) : new Uint8Array(0);
    const nonce = BigInt(await rpc(rpcUrl, 'eth_getTransactionCount', [from, 'pending']));
    const estimate = BigInt(await rpc(rpcUrl, 'eth_estimateGas',
      [{ from, to: target, value: qty(token ? 0n : value), data: '0x' + bytesToHex(data) }]));
    const gas = estimate === 21000n ? estimate : (estimate * 12n) / 10n;   // margin for contract calls
    const block = await rpc(rpcUrl, 'eth_getBlockByNumber', ['latest', false]);
    const tx = { chainId, nonce, gas, to: target, value: token ? 0n : value, data };
    if (block && block.baseFeePerGas) {
      let tip;
      try { tip = BigInt(await rpc(rpcUrl, 'eth_maxPriorityFeePerGas')); } catch (e) { tip = 1500000000n; }
      Object.assign(tx, { type: 2, maxPriorityFeePerGas: tip, maxFeePerGas: 2n * BigInt(block.baseFeePerGas) + tip });
    } else {
      Object.assign(tx, { type: 0, gasPrice: BigInt(await rpc(rpcUrl, 'eth_gasPrice')) });
    }
    tx.maxCost = tx.gas * (tx.type === 2 ? tx.maxFeePerGas : tx.gasPrice);
    tx.unsignedHex = bytesToHex(encodeEthTx(tx));
    return tx;
  }

  async function broadcastEthTx(rpcUrl, signedHex) {
    const h = signedHex.startsWith('0x') ? signedHex : '0x' + signedHex;
    return rpc(rpcUrl, 'eth_sendRawTransaction', [h]);
  }

  /* ---------- Bitcoin ---------- */

  const BTC_NETWORKS = {
    mainnet: { name: 'Bitcoin', api: 'https://mempool.space/api', web: 'https://mempool.space', hrp: 'bc' },
    testnet4: { name: 'Testnet4', api: 'https://mempool.space/testnet4/api', web: 'https://mempool.space/testnet4', hrp: 'tb' },
    testnet3: { name: 'Testnet3', api: 'https://mempool.space/testnet/api', web: 'https://mempool.space/testnet', hrp: 'tb' },
    signet: { name: 'Signet', api: 'https://mempool.space/signet/api', web: 'https://mempool.space/signet', hrp: 'tb' },
  };

  class Reader {
    constructor(bytes) { this.b = bytes; this.p = 0; }
    take(n) {
      if (this.p + n > this.b.length) throw new Error('truncated data');
      const s = this.b.subarray(this.p, this.p + n);
      this.p += n;
      return s;
    }
    u8() { return this.take(1)[0]; }
    le(n) { const s = this.take(n); let v = 0n; for (let i = n - 1; i >= 0; i--) v = (v << 8n) | BigInt(s[i]); return v; }
    varint() {
      const b = this.u8();
      if (b < 0xfd) return b;
      return Number(this.le(b === 0xfd ? 2 : b === 0xfe ? 4 : 8));
    }
    bytes() { return this.take(this.varint()); }
  }

  function varint(n) {
    if (n < 0xfd) return Uint8Array.of(n);
    if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, n >> 8);
    return Uint8Array.of(0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
  }
  const withLen = (b) => concat(varint(b.length), b);

  function parseTx(bytes) {
    const r = new Reader(bytes);
    const version = r.take(4);
    const vin = [];
    const nIn = r.varint();
    for (let i = 0; i < nIn; i++) vin.push({ outpoint: r.take(36), scriptSig: r.bytes(), sequence: r.take(4) });
    const vout = [];
    const nOut = r.varint();
    for (let i = 0; i < nOut; i++) vout.push({ value: r.le(8), script: r.bytes() });
    const locktime = r.take(4);
    if (r.p !== bytes.length) throw new Error('unexpected data after transaction');
    return { version, vin, vout, locktime };
  }

  function parsePsbt(bytes) {
    const r = new Reader(bytes);
    if (bytesToHex(r.take(5)) !== '70736274ff') throw new Error('not a PSBT');
    const readMap = () => {
      const m = [];
      for (;;) {
        const key = r.bytes();
        if (key.length === 0) return m;
        m.push({ key, value: r.bytes() });
      }
    };
    const global = readMap();
    const txEntry = global.find((e) => e.key.length === 1 && e.key[0] === 0x00);
    if (!txEntry) throw new Error('PSBT has no unsigned transaction');
    const tx = parseTx(txEntry.value);
    const inputs = tx.vin.map(readMap);
    const outputs = tx.vout.map(readMap);
    return { tx, inputs, outputs };
  }

  /* bech32 / bech32m (BIP173 / BIP350) for showing output addresses */
  const B32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  function bech32Polymod(values) {
    const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const top = chk >>> 25;
      chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
      for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk = (chk ^ G[i]) >>> 0;
    }
    return chk;
  }
  function segwitAddress(hrp, version, program) {
    const data = [version];
    let acc = 0, bits = 0;
    for (const b of program) {
      acc = (acc << 8) | b; bits += 8;
      while (bits >= 5) { bits -= 5; data.push((acc >>> bits) & 31); }
    }
    if (bits) data.push((acc << (5 - bits)) & 31);
    const exp = [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));
    const pm = (bech32Polymod(exp.concat(data, [0, 0, 0, 0, 0, 0])) ^ (version === 0 ? 1 : 0x2bc830a3)) >>> 0;
    const check = [0, 1, 2, 3, 4, 5].map((i) => (pm >>> (5 * (5 - i))) & 31);
    return hrp + '1' + data.concat(check).map((v) => B32[v]).join('');
  }
  function scriptToAddress(script, hrp) {
    const n = script.length;
    if (n >= 4 && n <= 42 && (script[0] === 0 || (script[0] >= 0x51 && script[0] <= 0x60)) && script[1] === n - 2) {
      return segwitAddress(hrp, script[0] === 0 ? 0 : script[0] - 0x50, script.subarray(2));
    }
    if (n > 0 && script[0] === 0x6a) return 'OP_RETURN data';
    return 'script ' + bytesToHex(script);   // legacy base58 forms not decoded here
  }

  async function sha256d(bytes) {
    const once = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    return new Uint8Array(await crypto.subtle.digest('SHA-256', once));
  }

  // Turn a PSBT signed by the device into a broadcastable transaction.
  // Native SegWit (P2WPKH) inputs: witness = [signature, pubkey].
  async function finalizePsbt(psbtBytes, network) {
    const net = BTC_NETWORKS[network];
    if (!net) throw new Error('unknown network ' + network);
    const { tx, inputs } = parsePsbt(psbtBytes);
    let inTotal = 0n;
    const witnesses = inputs.map((m, i) => {
      const utxo = m.find((e) => e.key.length === 1 && e.key[0] === 0x01);
      if (!utxo) throw new Error('input ' + i + ': no witness UTXO');
      const ur = new Reader(utxo.value);
      inTotal += ur.le(8);
      const final = m.find((e) => e.key.length === 1 && e.key[0] === 0x08);
      if (final) return final.value;                       // already finalized
      const script = ur.bytes();
      if (script.length !== 22 || script[0] !== 0 || script[1] !== 20) {
        throw new Error('input ' + i + ': only native SegWit (P2WPKH) inputs can be finalized here');
      }
      const sigs = m.filter((e) => e.key[0] === 0x02 && e.key.length === 34);
      if (sigs.length !== 1) throw new Error('input ' + i + ': not signed');
      return concat(varint(2), withLen(sigs[0].value), withLen(sigs[0].key.subarray(1)));
    });
    const body = [varint(tx.vin.length)];
    for (const v of tx.vin) body.push(v.outpoint, withLen(v.scriptSig), v.sequence);
    body.push(varint(tx.vout.length));
    let outTotal = 0n;
    for (const o of tx.vout) {
      outTotal += o.value;
      const value = new Uint8Array(8);
      let x = o.value;
      for (let i = 0; i < 8; i++) { value[i] = Number(x & 0xffn); x >>= 8n; }
      body.push(value, withLen(o.script));
    }
    const legacy = concat(tx.version, ...body, tx.locktime);
    const full = concat(tx.version, Uint8Array.of(0, 1), ...body, ...witnesses, tx.locktime);
    const txid = bytesToHex((await sha256d(legacy)).reverse());
    return {
      hex: bytesToHex(full),
      txid,
      vsize: Math.ceil((legacy.length * 3 + full.length) / 4),
      fee: inTotal - outTotal,
      outputs: tx.vout.map((o) => ({ address: scriptToAddress(o.script, net.hrp), value: o.value })),
    };
  }

  async function broadcastBtcTx(network, hex) {
    const net = BTC_NETWORKS[network];
    const res = await fetch(net.api + '/tx', { method: 'POST', body: hex });
    const text = (await res.text()).trim();
    if (!res.ok) throw new Error('broadcast rejected: ' + text);
    return text;   // txid
  }

  Object.assign(exports, {
    hexToBytes, bytesToHex, parseUnits, formatUnits, rlpEncode,
    EVM_NETWORKS, rpc, readToken, erc20TransferData, encodeEthTx, prepareEthTx, broadcastEthTx,
    BTC_NETWORKS, parsePsbt, scriptToAddress, finalizePsbt, broadcastBtcTx,
  });
})(typeof module !== 'undefined' && module.exports ? module.exports : (window.SoteriaChain = {}));
