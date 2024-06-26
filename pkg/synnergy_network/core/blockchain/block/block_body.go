package block

import (
    "crypto/sha256"
    "encoding/hex"
    "sync"
    "time"

    "github.com/pkg/errors"
)

// Transaction represents a single transaction within a block.
type Transaction struct {
    Sender    string
    Receiver  string
    Amount    float64
    Timestamp time.Time
    Signature string
}

// Block represents a block in the blockchain.
type Block struct {
    Header BlockHeader
    Body   BlockBody
}

// BlockHeader contains metadata about the block.
type BlockHeader struct {
    PreviousHash   string
    Timestamp      time.Time
    Nonce          int
    MerkleRootHash string
}

// BlockBody contains the transactional data.
type BlockBody struct {
    Transactions []Transaction
}

// Blockchain represents the blockchain.
type Blockchain struct {
    Blocks []Block
    mu     sync.Mutex
}

// NewTransaction creates a new transaction.
func NewTransaction(sender, receiver string, amount float64, signature string) Transaction {
    return Transaction{
        Sender:    sender,
        Receiver:  receiver,
        Amount:    amount,
        Timestamp: time.Now(),
        Signature: signature,
    }
}

// NewBlock creates a new block.
func NewBlock(previousHash string, transactions []Transaction, nonce int) (Block, error) {
    if len(transactions) == 0 {
        return Block{}, errors.New("no transactions to include in the block")
    }

    merkleRootHash := calculateMerkleRoot(transactions)
    header := BlockHeader{
        PreviousHash:   previousHash,
        Timestamp:      time.Now(),
        Nonce:          nonce,
        MerkleRootHash: merkleRootHash,
    }

    body := BlockBody{Transactions: transactions}
    return Block{Header: header, Body: body}, nil
}

// calculateMerkleRoot calculates the Merkle root of the transactions in the block.
func calculateMerkleRoot(transactions []Transaction) string {
    var transactionHashes []string
    for _, tx := range transactions {
        txHash := sha256.Sum256([]byte(tx.Sender + tx.Receiver + tx.Signature + string(tx.Amount) + tx.Timestamp.String()))
        transactionHashes = append(transactionHashes, hex.EncodeToString(txHash[:]))
    }

    for len(transactionHashes) > 1 {
        var newLevel []string
        for i := 0; i < len(transactionHashes); i += 2 {
            if i+1 < len(transactionHashes) {
                combinedHash := sha256.Sum256([]byte(transactionHashes[i] + transactionHashes[i+1]))
                newLevel = append(newLevel, hex.EncodeToString(combinedHash[:]))
            } else {
                newLevel = append(newLevel, transactionHashes[i])
            }
        }
        transactionHashes = newLevel
    }

    return transactionHashes[0]
}

// AddBlock adds a block to the blockchain.
func (bc *Blockchain) AddBlock(block Block) {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    bc.Blocks = append(bc.Blocks, block)
}

// ValidateBlock validates a block before adding it to the blockchain.
func (bc *Blockchain) ValidateBlock(block Block) error {
    if len(bc.Blocks) > 0 && bc.Blocks[len(bc.Blocks)-1].Header.PreviousHash != block.Header.PreviousHash {
        return errors.New("invalid previous hash")
    }

    calculatedMerkleRoot := calculateMerkleRoot(block.Body.Transactions)
    if calculatedMerkleRoot != block.Header.MerkleRootHash {
        return errors.New("invalid Merkle root")
    }

    // Further validation like proof of work, signature checks, etc., can be added here.

    return nil
}

// NewBlockchain initializes a new blockchain.
func NewBlockchain() *Blockchain {
    return &Blockchain{
        Blocks: []Block{},
        mu:     sync.Mutex{},
    }
}

// Mining is done with Argon2
func mineBlock(previousHash string, transactions []Transaction, difficulty int) (Block, error) {
    nonce := 0
    for {
        block, err := NewBlock(previousHash, transactions, nonce)
        if err != nil {
            return Block{}, err
        }

        hash := sha256.Sum256([]byte(block.Header.PreviousHash + block.Header.Timestamp.String() + string(block.Header.Nonce) + block.Header.MerkleRootHash))
        hashString := hex.EncodeToString(hash[:])

        if isValidHash(hashString, difficulty) {
            return block, nil
        }

        nonce++
    }
}

// isValidHash checks if the hash meets the difficulty criteria.
func isValidHash(hash string, difficulty int) bool {
    prefix := ""
    for i := 0; i < difficulty; i++ {
        prefix += "0"
    }
    return hash[:difficulty] == prefix
}
