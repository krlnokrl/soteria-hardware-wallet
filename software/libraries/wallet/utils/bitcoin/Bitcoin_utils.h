/*
 *  Transaction classes.
 *  Classes are defined in Transaction.cpp file.
 *  TODO: handle large transactions and invalid inputs somehow...
 */

class TransactionInput{
public:
    TransactionInput();
    TransactionInput(byte prev_id[32], uint32_t prev_index);
    TransactionInput(char prev_id_hex[], uint32_t prev_index);
    TransactionInput(byte prev_id[32], uint32_t prev_index, Script script, uint32_t sequence_number = 0xffffffff);
    TransactionInput(byte prev_id[32], uint32_t prev_index, uint32_t sequence_number, Script script);
    TransactionInput(TransactionInput const &other);
    TransactionInput &operator=(TransactionInput const &other);

    // TransactionInput(Stream & s){ parse(s); };
    // TransactionInput(byte raw[], size_t len){ parse(raw, len); };

    uint8_t hash[32];
    uint32_t outputIndex;
    Script scriptSig;
    uint32_t sequence;

    // For segwit:
    Script witnessProgram;
    uint64_t amount = 0; // required for signing, also used for fee calculation

    // following information is optional, 
    // can be obtained from spending output
    Script scriptPubKey;

    bool isSegwit();
    size_t parse(Stream &s);
    size_t parse(byte raw[], size_t len);
    size_t length(); // length of the serialized bytes sequence
    size_t length(Script script_pubkey); // length of the serialized bytes sequence with custom script
    size_t serialize(Stream &s); // serialize to Stream
    size_t serialize(Stream &s, Script script_pubkey); // serialize to stream with custom script
    size_t serialize(uint8_t array[], size_t len); // serialize to array
    size_t serialize(uint8_t array[], size_t len, Script script_pubkey); // use custom script for serialization
    operator String();
};

class TransactionOutput{
public:
    TransactionOutput();
    TransactionOutput(uint64_t send_amount, Script outputScript);
    TransactionOutput(uint64_t send_amount, char address[]);
    TransactionOutput(uint64_t send_amount, String address);
    TransactionOutput(Script outputScript, uint64_t send_amount);
    TransactionOutput(char address[], uint64_t send_amount);
    TransactionOutput(String address, uint64_t send_amount);
    TransactionOutput(TransactionOutput const &other);
    TransactionOutput &operator=(TransactionOutput const &other);
    // TransactionOutput(Stream & s){ parse(s); };
    // TransactionOutput(byte raw[], size_t len){ parse(raw, len); };

    uint64_t amount = 0;
    Script scriptPubKey;

    size_t parse(Stream &s);
    size_t parse(byte raw[], size_t l);
    String address(bool testnet=false);

    size_t length(); // length of the serialized bytes sequence
    size_t serialize(Stream &s); // serialize to Stream
    size_t serialize(uint8_t array[], size_t len); // serialize to array
    operator String();
};

class Transaction{
public:
    Transaction();
    Transaction(Stream &s){ parse(s); };
    Transaction(byte raw[], size_t len){ parse(raw, len); };
    ~Transaction();

    Transaction(Transaction const &other);
    Transaction &operator=(Transaction const &other);

    uint32_t version = 1;
    TransactionInput * txIns = NULL;
    TransactionOutput * txOuts = NULL;
    uint32_t locktime = 0;

    size_t parse(Stream &s);
    size_t parse(byte raw[], size_t len);
    size_t inputsNumber = 0;
    size_t outputsNumber = 0;
    uint8_t addInput(TransactionInput txIn);
    uint8_t addOutput(TransactionOutput txOut);

    size_t length(); // length of the serialized bytes sequence
    size_t serialize(Stream &s, bool segwit); // serialize to Stream
    size_t serialize(Stream &s); // serialize to Stream
    size_t serialize(uint8_t array[], size_t len); // serialize to array

    // populates hash with transaction hash
    int hash(uint8_t hash[32]);
    int id(uint8_t id_arr[32]); // populates array with id of the transaction (reverse of hash)
    String id(); // returns hex string with id of the transaction
    bool isSegwit();

    // populates hash with data for signing certain input with particular scriptPubkey
    int sigHash(uint8_t inputIndex, Script scriptPubKey, uint8_t hash[32]);

    int hashPrevouts(uint8_t hash[32]);
    int hashSequence(uint8_t hash[32]);
    int hashOutputs(uint8_t hash[32]);
    int sigHashSegwit(uint8_t inputIndex, Script scriptPubKey, uint8_t hash[32]);

    // signes input and returns scriptSig with signature and public key
    Signature signInput(uint8_t inputIndex, PrivateKey pk);
    Signature signInput(uint8_t inputIndex, PrivateKey pk, Script redeemScript);

    // TODO: sort() - bip69, Lexicographical Indexing of Transaction Inputs and Outputs
    operator String();
};