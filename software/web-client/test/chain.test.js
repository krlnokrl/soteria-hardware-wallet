// chain.js against reference vectors (rlp / eth_abi / embit, see
// ../../test/tools/make_web_fixtures.py) and a mocked JSON-RPC node.
const test = require('node:test');
const assert = require('node:assert');
const C = require('../chain.js');
const fx = require('./fixtures.json');

const big = (t) => {
  const tx = { ...t, data: C.hexToBytes(t.data) };
  for (const k of ['chainId', 'nonce', 'gas', 'value', 'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas']) {
    if (tx[k] !== undefined) tx[k] = BigInt(tx[k]);
  }
  return tx;
};

test('decimal units', () => {
  assert.strictEqual(C.parseUnits('1.5', 18), 1500000000000000000n);
  assert.strictEqual(C.parseUnits('.25', 2), 25n);
  for (const bad of ['', '.', '1.2.3', '-1', '1e5', '0.1234567']) {
    assert.throws(() => C.parseUnits(bad, 6), undefined, bad);
  }
  assert.strictEqual(C.formatUnits(1500000000000000000n, 18), '1.5');
  assert.strictEqual(C.formatUnits(0n, 6), '0');
});

test('unsigned Ethereum transactions match the rlp encoding', () => {
  for (const t of fx.eth) assert.strictEqual(C.bytesToHex(C.encodeEthTx(big(t))), t.expected);
});

test('ERC-20 transfer calldata matches eth_abi', () => {
  for (const e of fx.erc20) {
    assert.strictEqual(C.bytesToHex(C.erc20TransferData(e.to, BigInt(e.amount))), e.expected);
  }
});

test('signed PSBTs finalize to the same transaction as embit', async () => {
  for (const b of fx.btc) {
    const r = await C.finalizePsbt(Buffer.from(b.psbt, 'base64'), b.network);
    assert.strictEqual(r.hex, b.hex);
    assert.strictEqual(r.txid, b.txid);
    assert.strictEqual(r.fee, BigInt(b.fee));
    assert.strictEqual(r.vsize, b.vsize);
    assert.deepStrictEqual(r.outputs.map((o) => o.address), b.addresses);
  }
  await assert.rejects(C.finalizePsbt(Buffer.from(fx.btc[0].unsigned, 'base64'), 'mainnet'), /not signed/);
});

test('prepareEthTx asks the node for nonce, fees and gas', async () => {
  const calls = [];
  const node = (chainId, baseFee, estimate) => async (url, opts) => {
    const req = JSON.parse(opts.body);
    calls.push(req);
    const results = {
      eth_chainId: '0x' + chainId.toString(16),
      eth_getTransactionCount: '0x7',
      eth_estimateGas: '0x' + estimate.toString(16),
      eth_getBlockByNumber: baseFee ? { baseFeePerGas: '0x' + baseFee.toString(16) } : {},
      eth_maxPriorityFeePerGas: '0x3b9aca00',
      eth_gasPrice: '0x4a817c800',
    };
    return { ok: true, json: async () => ({ jsonrpc: '2.0', id: req.id, result: results[req.method] }) };
  };
  const from = '0x' + '11'.repeat(20), to = '0x' + '22'.repeat(20), token = '0x' + '33'.repeat(20);

  global.fetch = node(137, 30000000000n, 21000n);
  let tx = await C.prepareEthTx({ rpcUrl: 'x', chainId: 137, from, to, value: 10n ** 18n });
  assert.strictEqual(tx.type, 2);
  assert.strictEqual(tx.nonce, 7n);
  assert.strictEqual(tx.gas, 21000n);
  assert.strictEqual(tx.maxFeePerGas, 2n * 30000000000n + 1000000000n);
  assert.ok(calls.some((c) => c.method === 'eth_getTransactionCount' && c.params[1] === 'pending'));

  global.fetch = node(1, 10n, 50000n);
  tx = await C.prepareEthTx({ rpcUrl: 'x', chainId: 1, from, to, token, amount: 1000000n });
  assert.strictEqual(tx.to, token);
  assert.strictEqual(tx.value, 0n);
  assert.strictEqual(C.bytesToHex(tx.data), C.bytesToHex(C.erc20TransferData(to, 1000000n)));
  assert.strictEqual(tx.gas, 60000n);   // +20 % for contract calls

  global.fetch = node(56, null, 21000n);
  tx = await C.prepareEthTx({ rpcUrl: 'x', chainId: 56, from, to, value: 1n });
  assert.strictEqual(tx.type, 0);       // no base fee: legacy EIP-155

  global.fetch = node(1, 10n, 21000n);
  await assert.rejects(C.prepareEthTx({ rpcUrl: 'x', chainId: 137, from, to, value: 1n }), /chain 1, expected 137/);
});
