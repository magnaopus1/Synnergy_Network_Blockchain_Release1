package child_chain

// other code


import (
    "crypto/sha256"
    "encoding/hex"
    "strconv"
    "time"
)

type Transaction struct {
    From   string
    To     string
    Amount int
    Fee    int
}

func (tx Transaction) ToString() string {
    return tx.From + tx.To + strconv.Itoa(tx.Amount) + strconv.Itoa(tx.Fee)
}

type Block struct {
    Index        int
    Timestamp    string
    Transactions []Transaction
    PreviousHash string
    Hash         string
    Nonce        int
}

func calculateHash(block Block) string {
    record := strconv.Itoa(block.Index) + block.Timestamp + block.PreviousHash + strconv.Itoa(block.Nonce)
    for _, tx := range block.Transactions {
        record += tx.ToString()
    }
    hash := sha256.New()
    hash.Write([]byte(record))
    hashed := hash.Sum(nil)
    return hex.EncodeToString(hashed)
}

func createBlock(index int, transactions []Transaction, previousHash string) Block {
    timestamp := time.Now().String()
    nonce := 0
    block := Block{
        Index:        index,
        Timestamp:    timestamp,
        Transactions: transactions,
        PreviousHash: previousHash,
        Nonce:        nonce,
    }
    block.Hash = calculateHash(block)
    return block
}

func mineBlock(difficulty int, block Block) Block {
    target := make([]byte, difficulty)
    for i := 0; i < difficulty; i++ {
        target[i] = '0'
    }
    targetStr := string(target)
    
    for block.Hash[:difficulty] != targetStr {
        block.Nonce++
        block.Hash = calculateHash(block)
    }
    return block
}

func validateBlock(newBlock, previousBlock Block) bool {
    if newBlock.PreviousHash != previousBlock.Hash {
        return false
    }
    if calculateHash(newBlock) != newBlock.Hash {
        return false
    }
    return true
}

func validateTransactions(transactions []Transaction) bool {
    for _, tx := range transactions {
        if tx.Amount <= 0 {
            return false
        }
    }
    return true
}
