package child_chain

// other code


import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"

    "golang.org/x/crypto/scrypt"
)

// Transaction represents a blockchain transaction
type Transaction struct {
    From   string
    To     string
    Amount int
    Fee    int
    Nonce  int
    Hash   string
}

// Blockchain represents the blockchain structure
type Blockchain struct {
    Chain               []Block
    PendingTransactions []Transaction
    Difficulty          int
    MiningReward        int
    mu                  sync.Mutex
}

// Block represents a block in the blockchain
type Block struct {
    Index        int
    Timestamp    string
    Transactions []Transaction
    PreviousHash string
    Hash         string
    Nonce        int
}

// calculateTransactionHash calculates the hash for a transaction
func calculateTransactionHash(tx Transaction) string {
    record := tx.From + tx.To + fmt.Sprintf("%d%d%d", tx.Amount, tx.Fee, tx.Nonce)
    hash := sha256.New()
    hash.Write([]byte(record))
    return hex.EncodeToString(hash.Sum(nil))
}

// createTransaction creates a new transaction
func createTransaction(from, to string, amount, fee, nonce int) (Transaction, error) {
    if from == "" || to == "" {
        return Transaction{}, errors.New("from and to addresses must not be empty")
    }
    if amount <= 0 || fee < 0 {
        return Transaction{}, errors.New("amount must be greater than zero and fee must be non-negative")
    }
    tx := Transaction{
        From:   from,
        To:     to,
        Amount: amount,
        Fee:    fee,
        Nonce:  nonce,
    }
    tx.Hash = calculateTransactionHash(tx)
    return tx, nil
}

// validateTransaction validates a transaction
func validateTransaction(tx Transaction) error {
    if tx.Hash != calculateTransactionHash(tx) {
        return errors.New("invalid transaction hash")
    }
    // Add additional validation logic if necessary
    return nil
}

// processTransaction processes a transaction and adds it to the blockchain's pending transactions
func (bc *Blockchain) processTransaction(tx Transaction) error {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    if err := validateTransaction(tx); err != nil {
        return err
    }

    bc.PendingTransactions = append(bc.PendingTransactions, tx)
    return nil
}

// createWallet creates a new wallet with a private and public key
func createWallet(password string) (string, string, error) {
    salt := make([]byte, 16)
    if _, err := time.Read(salt); err != nil {
        return "", "", err
    }

    dk, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
    if err != nil {
        return "", "", err
    }

    privateKey := hex.EncodeToString(dk)
    publicKey := hex.EncodeToString(dk[:16]) // Simplified public key generation

    return privateKey, publicKey, nil
}

// signTransaction signs a transaction using a private key
func signTransaction(tx Transaction, privateKey string) (string, error) {
    // Simplified signing logic
    record := tx.Hash + privateKey
    hash := sha256.New()
    hash.Write([]byte(record))
    return hex.EncodeToString(hash.Sum(nil)), nil
}

// verifyTransactionSignature verifies the transaction signature using a public key
func verifyTransactionSignature(tx Transaction, signature, publicKey string) bool {
    // Simplified verification logic
    record := tx.Hash + publicKey
    hash := sha256.New()
    hash.Write([]byte(record))
    return hex.EncodeToString(hash.Sum(nil)) == signature
}

// getPendingTransactions retrieves the list of pending transactions
func (bc *Blockchain) getPendingTransactions() []Transaction {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    return bc.PendingTransactions
}

// clearPendingTransactions clears the list of pending transactions
func (bc *Blockchain) clearPendingTransactions() {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    bc.PendingTransactions = []Transaction{}
}

// getBalance retrieves the balance for a given address
func (bc *Blockchain) getBalance(address string) int {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    balance := 0
    for _, block := range bc.Chain {
        for _, tx := range block.Transactions {
            if tx.To == address {
                balance += tx.Amount
            }
            if tx.From == address {
                balance -= tx.Amount
            }
        }
    }
    return balance
}

// createGenesisBlock creates the genesis block
func createGenesisBlock() Block {
    return Block{
        Index:        0,
        Timestamp:    time.Now().String(),
        Transactions: []Transaction{},
        PreviousHash: "0",
        Hash:         "",
        Nonce:        0,
    }
}

// initializeBlockchain initializes the blockchain with the genesis block
func initializeBlockchain() *Blockchain {
    genesisBlock := createGenesisBlock()
    genesisBlock.Hash = calculateBlockHash(genesisBlock)
    return &Blockchain{
        Chain:               []Block{genesisBlock},
        PendingTransactions: []Transaction{},
        Difficulty:          4,
        MiningReward:        100,
    }
}

// calculateBlockHash calculates the hash for a block
func calculateBlockHash(block Block) string {
    record := fmt.Sprintf("%d%s%d%s%s", block.Index, block.Timestamp, block.Nonce, block.PreviousHash, calculateTransactionsHash(block.Transactions))
    hash := sha256.New()
    hash.Write([]byte(record))
    return hex.EncodeToString(hash.Sum(nil))
}

// calculateTransactionsHash calculates the hash for a list of transactions
func calculateTransactionsHash(transactions []Transaction) string {
    record := ""
    for _, tx := range transactions {
        record += tx.Hash
    }
    hash := sha256.New()
    hash.Write([]byte(record))
    return hex.EncodeToString(hash.Sum(nil))
}

// mineBlock mines a new block with the pending transactions
func (bc *Blockchain) mineBlock(minerAddress string) (Block, error) {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    if len(bc.PendingTransactions) == 0 {
        return Block{}, errors.New("no transactions to mine")
    }

    newBlock := Block{
        Index:        len(bc.Chain),
        Timestamp:    time.Now().String(),
        Transactions: append(bc.PendingTransactions, Transaction{From: "system", To: minerAddress, Amount: bc.MiningReward}),
        PreviousHash: bc.Chain[len(bc.Chain)-1].Hash,
        Nonce:        0,
    }

    for !isValidHash(newBlock.Hash, bc.Difficulty) {
        newBlock.Nonce++
        newBlock.Hash = calculateBlockHash(newBlock)
    }

    bc.Chain = append(bc.Chain, newBlock)
    bc.PendingTransactions = []Transaction{}
    return newBlock, nil
}

// isValidHash checks if a hash meets the difficulty requirement
func isValidHash(hash string, difficulty int) bool {
    prefix := ""
    for i := 0; i < difficulty; i++ {
        prefix += "0"
    }
    return hash[:difficulty] == prefix
}
