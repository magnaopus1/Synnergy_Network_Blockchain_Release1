package block

import (
    "crypto/sha256"
    "crypto/x509"
    "encoding/hex"
    "encoding/pem"
    "errors"
    "fmt"
    "time"
    "golang.org/x/crypto/argon2"
)

// BlockHeader struct defines the elements of a block header
type BlockHeader struct {
    PreviousHash string
    Timestamp    int64
    Nonce        int
    MerkleRoot   string
}

// Block struct defines the elements of a block in the blockchain
type Block struct {
    Header BlockHeader
    Body   []Transaction
}

// Transaction struct to hold details of transactions
type Transaction struct {
    Sender    string
    Recipient string
    Amount    float64
    Signature string // Digital signature to ensure integrity
}

// CreateBlock creates a new block using previous block's hash and transaction data
func CreateBlock(previousHash string, transactions []Transaction) *Block {
    block := &Block{
        Header: BlockHeader{
            PreviousHash: previousHash,
            Timestamp:    time.Now().Unix(),
            Nonce:        0, // Nonce will be set after mining
            MerkleRoot:   getMerkleRoot(transactions),
        },
        Body: transactions,
    }
    return block
}

// CalculateHash calculates and returns the hash of the block's header
func (b *Block) CalculateHash() string {
    record := b.Header.PreviousHash + string(b.Header.Timestamp) + string(b.Header.Nonce) + b.Header.MerkleRoot
    h := sha256.New()
    h.Write([]byte(record))
    hashed := h.Sum(nil)
    return hex.EncodeToString(hashed)
}

// MineBlock performs the mining operation using PoW consensus algorithm
func (b *Block) MineBlock(difficulty int) {
    var str string
    for i := 0; i < difficulty; i++ {
        str += "0"
    }

    for b.CalculateHash()[:difficulty] != str {
        b.Header.Nonce++
    }
}

// getMerkleRoot calculates the Merkle root of the transactions in the block
func getMerkleRoot(transactions []Transaction) string {
    var transactionHashes []string
    for _, tx := range transactions {
        transactionHashes = append(transactionHashes, tx.CalculateHash())
    }
    // Placeholder: Implement Merkle Tree computation logic here
    return computeMerkleRoot(transactionHashes)
}

// Transaction.CalculateHash method to compute hash of the transaction
func (tx *Transaction) CalculateHash() string {
    record := tx.Sender + tx.Recipient + fmt.Sprintf("%f", tx.Amount) + tx.Signature
    h := sha256.New()
    h.Write([]byte(record))
    return hex.EncodeToString(h.Sum(nil))
}

// ValidateTransaction checks the integrity and authenticity of a transaction
func ValidateTransaction(tx Transaction) error {
    if tx.Sender == "" || tx.Recipient == "" {
        return errors.New("sender or recipient cannot be empty")
    }

    // Simulate public key retrieval and validation; in real scenario, fetch from a public key infrastructure
    pubKey, _ := x509.ParsePKIXPublicKey([]byte(tx.Sender))
    if !VerifyTransactionSignature(tx, pubKey.(*ecdsa.PublicKey)) {
        return errors.New("invalid transaction signature")
    }

    return nil
}

// VerifyTransactionSignature checks if the transaction's signature is valid
func VerifyTransactionSignature(tx Transaction, pubKey *ecdsa.PublicKey) bool {
    sigBytes, _ := hex.DecodeString(tx.Signature)
    return ecdsa.Verify(pubKey, []byte(tx.CalculateHash()), new(big.Int).SetBytes(sigBytes[:len(sigBytes)/2]), new(big.Int).SetBytes(sigBytes[len(sigBytes)/2:]))
}

// Error handling and utility functions can be further expanded based on specific needs
