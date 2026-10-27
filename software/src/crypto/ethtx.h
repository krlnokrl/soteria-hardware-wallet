#ifndef SOTERIA_ETHTX_H
#define SOTERIA_ETHTX_H

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Ethereum transaction parsing / re-encoding (RLP)                    */
/*                                                                     */
/* The host sends the *unsigned* serialized transaction; the device    */
/* parses it so the user sees recipient, value and fee, signs          */
/* keccak256(raw) and returns the signed serialization. Supported:     */
/*   - legacy with EIP-155 replay protection:                          */
/*       rlp([nonce, gasPrice, gas, to, value, data, chainId, 0, 0])   */
/*   - EIP-1559 (type 2):                                               */
/*       0x02 || rlp([chainId, nonce, maxPriorityFee, maxFee, gas,     */
/*                    to, value, data, accessList])                    */
/* Pointers in EthTx point into the caller's raw buffer.               */
/* ------------------------------------------------------------------ */

struct EthTx {
    uint8_t  type;               // 0 = legacy (EIP-155), 2 = EIP-1559
    uint64_t chainId;
    const uint8_t* to;           // NULL for contract creation
    const uint8_t* value;        // big-endian integer
    uint8_t  valueLen;
    const uint8_t* gasLimit;
    uint8_t  gasLimitLen;
    const uint8_t* maxFee;       // gasPrice (legacy) / maxFeePerGas (type 2)
    uint8_t  maxFeeLen;
    const uint8_t* data;         // contract calldata
    size_t   dataLen;
    const uint8_t* keep;         // encoded fields carried into the signed tx
    size_t   keepLen;
};

// Parse an unsigned transaction; false if malformed or unsupported
// (pre-EIP-155 legacy, type 1, trailing bytes, ...).
bool ethTxParse(const uint8_t* raw, size_t len, EthTx& tx);

// Serialize the signed transaction. sig = r(32) | s(32) | recovery id.
// Returns the length written, or 0 if it does not fit in cap.
size_t ethTxEncodeSigned(const EthTx& tx, const uint8_t sig[65], uint8_t* out, size_t cap);

// Upper bound of the fee: gasLimit * maxFee as a 32-byte big-endian
// integer. False if the product does not fit in 256 bits.
bool ethTxMaxFee(const EthTx& tx, uint8_t out[32]);

// Format a big-endian integer (<= 32 bytes) scaled by 10^decimals as a
// decimal string without trailing zeros ("0.0021"). Returns the length,
// or 0 if cap is too small.
size_t ethFormatUnits(const uint8_t* be, size_t len, uint8_t decimals, char* out, size_t cap);

// EIP-191 personal_sign digest:
// keccak256("\x19Ethereum Signed Message:\n" + decimal(len) + msg)
void ethPersonalMessageHash(const uint8_t* msg, size_t len, uint8_t hash[32]);

/* ------------------------------------------------------------------ */
/* ERC-20 calls                                                        */
/*                                                                     */
/* Recognised by selector and exact ABI shape. The device cannot know   */
/* whether the contract really is a token, only that the calldata has   */
/* the shape of an ERC-20 call (tx.to is then the token contract).      */
/* ------------------------------------------------------------------ */

enum Erc20Kind {
    ERC20_NONE = 0,
    ERC20_TRANSFER,          // transfer(address to, uint256 amount)
    ERC20_APPROVE,           // approve(address spender, uint256 amount)
    ERC20_TRANSFER_FROM,     // transferFrom(address from, address to, uint256 amount)
};

struct Erc20Call {
    Erc20Kind kind;
    const uint8_t* from;     // transferFrom only (20 bytes)
    const uint8_t* to;       // recipient, or spender for approve (20 bytes)
    const uint8_t* amount;   // 32-byte big-endian, in the token's base units
};

// False (kind = ERC20_NONE) if tx is not a well-formed ERC-20 call.
bool ethDecodeErc20(const EthTx& tx, Erc20Call& call);

// True for 2^256 - 1, the conventional "unlimited" approval.
bool ethIsMaxUint256(const uint8_t v[32]);

/* ------------------------------------------------------------------ */
/* EVM chains                                                          */
/* ------------------------------------------------------------------ */

struct EthChain {
    uint64_t id;
    const char* name;
    const char* symbol;      // native coin, 18 decimals
};

// Known chain, or NULL. All EVM chains share the same key and address.
const EthChain* ethChainLookup(uint64_t id);

#endif // SOTERIA_ETHTX_H
