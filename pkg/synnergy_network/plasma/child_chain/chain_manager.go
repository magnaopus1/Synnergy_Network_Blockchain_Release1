package child_chain

// other code


import (
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"

    "golang.org/x/crypto/scrypt"
)

type Blockchain struct {
    Chain               []Block
    PendingTransactions []Transaction
    Difficulty          int
    MiningReward        int
    mu                  sync.Mutex
}

func createGenesisBlock() Block {
    return createBlock(0, []Transaction{}, "0")
}

func initializeBlockchain() *Blockchain {
    return &Blockchain{
        Chain:               []Block{createGenesisBlock()},
        Difficulty:          4,
        MiningReward:        100,
        PendingTransactions: []Transaction{},
    }
}

func (bc *Blockchain) getLatestBlock() Block {
    bc.mu.Lock()
    defer bc.mu.Unlock()
    return bc.Chain[len(bc.Chain)-1]
}

func (bc *Blockchain) addTransaction(transaction Transaction) error {
    bc.mu.Lock()
    defer bc.mu.Unlock()
    
    if !validateTransaction(transaction) {
        return errors.New("invalid transaction")
    }
    
    bc.PendingTransactions = append(bc.PendingTransactions, transaction)
    return nil
}

func (bc *Blockchain) minePendingTransactions(miningRewardAddress string) (Block, error) {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    if len(bc.PendingTransactions) == 0 {
        return Block{}, errors.New("no transactions to mine")
    }

    newBlock := createBlock(len(bc.Chain), bc.PendingTransactions, bc.getLatestBlock().Hash)
    minedBlock := mineBlock(bc.Difficulty, newBlock)

    bc.Chain = append(bc.Chain, minedBlock)
    bc.PendingTransactions = []Transaction{
        {"SYSTEM", miningRewardAddress, bc.MiningReward, 0},
    }
    return minedBlock, nil
}

func (bc *Blockchain) isChainValid() bool {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    for i := 1; i < len(bc.Chain); i++ {
        currentBlock := bc.Chain[i]
        previousBlock := bc.Chain[i-1]

        if currentBlock.PreviousHash != previousBlock.Hash {
            return false
        }

        if calculateHash(currentBlock) != currentBlock.Hash {
            return false
        }
    }
    return true
}

func validateTransaction(tx Transaction) bool {
    // Add advanced transaction validation logic here
    if tx.Amount <= 0 || tx.From == "" || tx.To == "" {
        return false
    }
    return true
}

func createWallet() (string, string, error) {
    password := "securepassword" // Use a securely generated password
    salt := make([]byte, 16)
    _, err := time.Read(salt)
    if err != nil {
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

func main() {
    blockchain := initializeBlockchain()

    fmt.Println("Genesis Block created")
    fmt.Printf("%+v\n", blockchain.getLatestBlock())

    // Create some transactions
    blockchain.addTransaction(Transaction{"Alice", "Bob", 50, 1})
    blockchain.addTransaction(Transaction{"Bob", "Charlie", 30, 1})

    // Mine pending transactions
    minedBlock, err := blockchain.minePendingTransactions("Miner1")
    if err != nil {
        fmt.Println("Error mining block:", err)
    } else {
        fmt.Println("Block mined:")
        fmt.Printf("%+v\n", minedBlock)
    }

    // Check the balance of an address
    balance := blockchain.getBalance("Bob")
    fmt.Println("Bob's balance:", balance)

    // Validate the blockchain
    isValid := blockchain.isChainValid()
    fmt.Println("Blockchain valid:", isValid)
}
