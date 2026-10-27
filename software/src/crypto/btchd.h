#ifndef SOTERIA_BTCHD_H
#define SOTERIA_BTCHD_H

#include <Bitcoin.h>
#include <PSBT.h>
#include "Key.h"

/* ------------------------------------------------------------------ */
/* Bitcoin HD wallet: BIP84 (native SegWit, P2WPKH) accounts           */
/* m/84'/0'/0' (mainnet) and m/84'/1'/0' (testnet), output descriptors, */
/* and PSBT (BIP174) review and signing.                                */
/* ------------------------------------------------------------------ */

// Fill rec from the wallet root; the root is XOR-encrypted with the PIN.
void hdMakeRecord(const HDPrivateKey &root, const uint8_t pin[5], HdRecord &rec);

// Decrypt the root with pin; false if the PIN is wrong.
bool hdUnlock(const HdRecord &rec, const uint8_t pin[5], HDPrivateKey &root);

// Receive (change = 0) or change (1) address #index, e.g. "bc1q...".
size_t hdAddress(const HdRecord &rec, bool testnet, uint32_t change, uint32_t index,
                 char *out, size_t cap);

// Output descriptor with checksum, e.g.
// "wpkh([d34db33f/84h/0h/0h]xpub.../0/*)#abcd1234".
size_t hdDescriptor(const HdRecord &rec, bool testnet, uint32_t change, char *out, size_t cap);

// Address text for a scriptPubKey: base58 (P2PKH/P2SH), bech32 (SegWit
// v0) or bech32m (v1+, e.g. Taproot). 0 if it has no address form.
size_t btcScriptAddress(const Script &spk, bool testnet, char *out, size_t cap);

// Strict, bounds-checked structure checks for host-supplied data. They
// must pass BEFORE uBitcoin parses it: uBitcoin's transaction and PSBT
// parsers corrupt memory on some malformed inputs (e.g. an invalid
// pubkey in a BIP32 derivation leaves an uninitialised pointer that is
// later freed). Unsigned PSBTs for single-signature wallets only.
bool btcTxWellFormed(const uint8_t *raw, size_t len);
bool psbtWellFormed(const uint8_t *raw, size_t len);

// The original PSBT with psbt's partial signatures added to each input
// map (uBitcoin's own serializer drops UTXOs, derivations etc.).
// Returns the length, or 0 if it does not fit in cap.
size_t psbtMergeSignatures(const uint8_t *raw, size_t len, const PSBT &psbt,
                           uint8_t *out, size_t cap);

enum PsbtStatus {
    PSBT_OK = 0,
    PSBT_MISSING_UTXO,      // an input lacks its previous output (amount unknown)
    PSBT_NOT_OURS,          // no input belongs to this wallet's BIP84 account
    PSBT_BAD_AMOUNTS,       // outputs exceed inputs
    PSBT_UNDISPLAYABLE,     // an output script cannot be shown as an address
    PSBT_TOO_MANY_OUTPUTS,  // more than 64 outputs
};

struct PsbtSummary {
    uint64_t inputTotal;
    uint64_t sendTotal;     // to outputs that are not ours
    uint64_t ownTotal;      // change / transfers to our own addresses
    uint64_t fee;
    uint64_t ownOutputs;    // bit i set: output i pays to this wallet
    uint8_t  ownInputs;
};

// Check a parsed PSBT against the wallet and total it up. An output only
// counts as ours if its derivation path, derived key and script all match.
PsbtStatus psbtReview(const PSBT &psbt, const HdRecord &rec, bool testnet, PsbtSummary &sum);

// Add signatures for every input of this wallet; returns how many.
uint8_t psbtSign(PSBT &psbt, const HDPrivateKey &root);

#endif // SOTERIA_BTCHD_H
