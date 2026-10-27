"""Regenerate web-client/test/fixtures.json: reference vectors for chain.js.

Computed with independent libraries, so chain.js is checked against them:
  Ethereum: rlp + eth_abi;  Bitcoin: embit (PSBT signing, finalization, txid).

    pip install rlp eth-abi eth-utils embit
    python test/tools/make_web_fixtures.py

Not run in CI; the generated file is committed.
"""
import base64
import json
import os
import random

import rlp
from embit import bip32, bip39, ec, script
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput, Witness
from eth_abi import encode
from eth_utils import function_signature_to_4byte_selector as sel

rnd = random.Random(42)
rb = lambda n: bytes(rnd.getrandbits(8) for _ in range(n))
fx = {"eth": [], "erc20": [], "btc": []}

for i in range(20):
    t = {"chainId": rnd.choice([1, 137, 56, 11155111, rnd.randrange(1, 2**40)]),
         "nonce": rnd.choice([0, 1, 127, 128, rnd.randrange(2**32)]),
         "gas": rnd.choice([21000, rnd.randrange(21000, 10**7)]),
         "to": "0x" + rb(20).hex(), "value": rnd.choice([0, 1, 10**18, rnd.randrange(2**200)]),
         "data": rb(rnd.choice([0, 0, 68, 300])).hex()}
    to, data = bytes.fromhex(t["to"][2:]), bytes.fromhex(t["data"])
    if i % 2:
        t.update(type=2, maxPriorityFeePerGas=rnd.randrange(10**10), maxFeePerGas=rnd.randrange(10**8, 10**12))
        raw = b"\x02" + rlp.encode([t["chainId"], t["nonce"], t["maxPriorityFeePerGas"], t["maxFeePerGas"],
                                    t["gas"], to, t["value"], data, []])
    else:
        t.update(type=0, gasPrice=rnd.randrange(1, 10**12))
        raw = rlp.encode([t["nonce"], t["gasPrice"], t["gas"], to, t["value"], data, t["chainId"], 0, 0])
    t = {k: (str(v) if isinstance(v, int) and k != "type" else v) for k, v in t.items()}
    t["expected"] = raw.hex()
    fx["eth"].append(t)

for _ in range(5):
    to, amount = "0x" + rb(20).hex(), rnd.choice([0, 1, 10**6, 2**256 - 1, rnd.randrange(2**128)])
    fx["erc20"].append({"to": to, "amount": str(amount),
                        "expected": (sel("transfer(address,uint256)") + encode(["address", "uint256"], [to, amount])).hex()})

root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed("abandon " * 11 + "about"))
for coin, netname, n_in in [(0, "main", 1), (1, "test", 2)]:
    vin, metas = [], []
    for i in range(n_in):
        path = f"m/84h/{coin}h/0h/0/{i}"
        key = root.derive(path).key.get_public_key()
        spk = script.p2wpkh(key)
        value = 40_000 + 1000 * i
        vin.append(TransactionInput(rb(32), 0, sequence=0xfffffffd))
        metas.append((spk, key, path, value))
    outs = [TransactionOutput(25_000, script.p2tr(ec.PrivateKey(rb(32)).get_public_key())),
            TransactionOutput(10_000, script.p2wpkh(ec.PrivateKey(rb(32)).get_public_key())),
            TransactionOutput(0, script.Script(b"\x6a\x03abc"))]
    tx = Transaction(vin=vin, vout=outs, locktime=rnd.randrange(800000))
    p = PSBT(tx)
    for i, (spk, key, path, value) in enumerate(metas):
        p.inputs[i].witness_utxo = TransactionOutput(value, spk)
        p.inputs[i].bip32_derivations[key] = DerivationPath(root.my_fingerprint, bip32.parse_path(path))
    unsigned = base64.b64encode(p.serialize()).decode()
    p.sign_with(root)
    final = Transaction.parse(tx.serialize())
    for i, inp in enumerate(p.inputs):
        (pub, sig), = inp.partial_sigs.items()
        final.vin[i].witness = Witness([sig, pub.sec()])
    fx["btc"].append({
        "network": "mainnet" if coin == 0 else "testnet4",
        "unsigned": unsigned,
        "psbt": base64.b64encode(p.serialize()).decode(),
        "hex": final.serialize().hex(), "txid": final.txid().hex(),
        "fee": sum(m[3] for m in metas) - 35_000,
        "vsize": -(-(len(tx.serialize()) * 3 + len(final.serialize())) // 4),
        "addresses": [o.script_pubkey.address(NETWORKS[netname]) for o in outs[:2]] + ["OP_RETURN data"],
    })

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "web-client", "test", "fixtures.json")
with open(out, "w") as f:
    json.dump(fx, f, indent=1)
print("wrote", os.path.normpath(out))
