package consensus

import (
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "math/big"
    "strings"
    "sync"
    "time"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

type MiningProcess struct {
    Blockchain        []*Block
    TransactionPool   []Transaction
    BlockReward       float64
    Difficulty        int
    NetworkHashrate   float64
    MiningTarget      string
    HalvingInterval   int
    BlockInterval     time.Duration
    MinerConfig       *MinerConfig
    lock              sync.Mutex
}

type MinerConfig struct {
    Memory      uint32
    Iterations  uint32
    Parallelism uint8
    SaltLength  uint32
    KeyLength   uint32
    Algorithm   string // Indicates current hashing algorithm
}

type Transaction struct {
    Sender    string
    Receiver  string
    Amount    float64
    Fee       float64
    Signature string // Assuming ECDSA or similar
}

type Block struct {
    Timestamp     int64
    Transactions  []Transaction
    PrevBlockHash string
    Nonce         uint64
    Hash          string
}

func NewMiningProcess() *MiningProcess {
    mc := &MinerConfig{
        Memory:      64 * 1024,
        Iterations:  1,
        Parallelism: 4,
        SaltLength:  16,
        KeyLength:   32,
        Algorithm:   "argon2", // Default to Argon2
    }

    mp := &MiningProcess{
        Blockchain:      make([]*Block, 0),
        TransactionPool: make([]Transaction, 0),
        BlockReward:     1252,
        Difficulty:      16,
        HalvingInterval: 200000,
        BlockInterval:   10 * time.Minute,
        MinerConfig:     mc,
    }
    mp.calculateMiningTarget()
    return mp
}

func (mp *MiningProcess) calculateMiningTarget() {
    target := big.NewInt(1)
    target.Lsh(target, uint(256-mp.Difficulty))
    mp.MiningTarget = target.Text(16)
}

func (mp *MiningProcess) MineBlock() (*Block, error) {
    mp.lock.Lock()
    defer mp.lock.Unlock()

    block := &Block{
        Timestamp:    time.Now().Unix(),
        Transactions: mp.TransactionPool,
        PrevBlockHash: func() string {
            if len(mp.Blockchain) > 0 {
                return mp.Blockchain[len(mp.Blockchain)-1].Hash
            }
            return ""
        }(),
    }

    // Switch hashing algorithm if needed
    mp.switchHashingAlgorithm()

    for nonce := uint64(0); ; nonce++ {
        block.Nonce = nonce
        if hash, err := mp.CalculateBlockHash(block); err == nil && mp.ValidateBlockHash(hash) {
            block.Hash = hash
            break
        }
    }

    mp.TransactionPool = []Transaction{}
    mp.Blockchain = append(mp.Blockchain, block)

    mp.adjustDifficulty()
    mp.adjustBlockReward()

    return block, nil
}

func (mp *MiningProcess) CalculateBlockHash(block *Block) (string, error) {
    data := fmt.Sprintf("%d:%s:%d", block.Timestamp, block.PrevBlockHash, block.Nonce)
    salt, err := rand.Prime(rand.Reader, 128) // Generate a random prime as salt
    if err != nil {
        return "", err
    }

    var hash []byte
    switch mp.MinerConfig.Algorithm {
    case "argon2":
        hash = argon2.IDKey([]byte(data), salt.Bytes(), mp.MinerConfig.Iterations, mp.MinerConfig.Memory, mp.MinerConfig.Parallelism, mp.MinerConfig.KeyLength)
    case "scrypt":
        hash, err = scrypt.Key([]byte(data), salt.Bytes(), int(mp.MinerConfig.Iterations), int(mp.MinerConfig.Memory), int(mp.MinerConfig.Parallelism), int(mp.MinerConfig.KeyLength))
        if err != nil {
            return "", err
        }
    case "sha256":
        hasher := sha256.New()
        hasher.Write([]byte(data))
        hash = hasher.Sum(nil)
    default:
        return "", errors.New("unsupported hashing algorithm")
    }

    return hex.EncodeToString(hash), nil
}

func (mp *MiningProcess) ValidateBlockHash(hash string) bool {
    targetHash, _ := new(big.Int).SetString(mp.MiningTarget, 16)
    blockHash, _ := new(big.Int).SetString(hash, 16)
    return blockHash.Cmp(targetHash) == -1
}

func (mp *MiningProcess) adjustDifficulty() {
    if len(mp.Blockchain)%2016 == 0 && len(mp.Blockchain) > 0 {
        expectedTime := int64(mp.BlockInterval.Seconds() * 2016)
        actualTime := mp.Blockchain[len(mp.Blockchain)-1].Timestamp - mp.Blockchain[len(mp.Blockchain)-2016].Timestamp
        if actualTime < expectedTime {
            mp.Difficulty++
        } else if actualTime > expectedTime {
            mp.Difficulty--
        }
        mp.calculateMiningTarget()
    }
}

func (mp *MiningProcess) adjustBlockReward() {
    if len(mp.Blockchain)%mp.HalvingInterval == 0 && len(mp.Blockchain) > 0 {
        mp.BlockReward /= 2
    }
}

func (mp *MiningProcess) switchHashingAlgorithm() {
    const performanceThreshold = 1000000 // Example threshold for hashrate in H/s

    // Check the current network hashrate and switch algorithms accordingly
    if mp.NetworkHashrate < performanceThreshold {
        mp.MinerConfig.Algorithm = "scrypt" // Use Scrypt for lower energy and compute requirements
        fmt.Println("Switched to Scrypt due to low network hashrate.")
    } else {
        mp.MinerConfig.Algorithm = "argon2" // Default to Argon2 for enhanced security
        fmt.Println("Using Argon2 for optimal security.")
    }
}

func (mp *MiningProcess) AddTransaction(tx Transaction) error {
    mp.lock.Lock()
    defer mp.lock.Unlock()

    // Check for double spending by ensuring no other pending transaction from the same sender has the same amount and receiver
    for _, transaction := range mp.TransactionPool {
        if transaction.Sender == tx.Sender && transaction.Amount == tx.Amount && transaction.Receiver == tx.Receiver {
            return errors.New("double spending attempt detected")
        }
    }

    // Validate the transaction signature
    if !validateSignature(tx) {
        return errors.New("invalid transaction signature")
    }

    // Add the transaction to the pool if all checks pass
    mp.TransactionPool = append(mp.TransactionPool, tx)
    fmt.Println("Transaction added successfully")
    return nil
}

func validateSignature(tx Transaction) bool {
    // Simulate getting the public key (this should actually be fetched based on sender's address)
    publicKey := getPublicKey(tx.Sender) // Assume this function retrieves the ECDSA public key for the sender

    // Decode the hex signature
    sigR, sigS := new(big.Int), new(big.Int)
    sigLen := len(tx.Signature)
    rHex, sHex := tx.Signature[:sigLen/2], tx.Signature[sigLen/2:]
    sigR.SetString(rHex, 16)
    sigS.SetString(sHex, 16)

    // Create the hash of the transaction details
    hasher := sha256.New()
    hasher.Write([]byte(fmt.Sprintf("%s:%s:%f:%f", tx.Sender, tx.Receiver, tx.Amount, tx.Fee)))
    hash := hasher.Sum(nil)

    // Verify the signature
    ecdsaPublicKey := publicKey.(*ecdsa.PublicKey)
    return ecdsa.Verify(ecdsaPublicKey, hash, sigR, sigS)
}

// This function is a placeholder and needs proper implementation based on your system
func getPublicKey(sender string) interface{} {
    // This should return the actual public key object associated with a sender's address
    return &ecdsa.PublicKey{} // Placeholder return
}
