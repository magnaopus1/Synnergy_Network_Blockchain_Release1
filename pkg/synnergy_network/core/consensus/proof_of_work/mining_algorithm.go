package consensus

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"math/big"
	"time"
	"synthron-blockchain/pkg/synnergy_network/core/common"
)

type MinerConfig struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
	Algorithm   string
}

func DefaultMinerConfig() *MinerConfig {
	return &MinerConfig{
		Memory:      64 * 1024, // 64 MB
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
		Algorithm:   "argon2", // Default algorithm
	}
}

func GenerateSalt(length uint32) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	return salt, err
}

func CalculateHash(block *common.Block, config *MinerConfig) (string, error) {
	salt, err := GenerateSalt(config.SaltLength)
	if err != nil {
		return "", err
	}

	data := blockData(block)

	var hash []byte
	switch config.Algorithm {
	case "argon2":
		hash = argon2.IDKey(data, salt, config.Iterations, config.Memory, config.Parallelism, config.KeyLength)
	case "scrypt":
		hash, _ = scrypt.Key(data, salt, int(config.Iterations), int(config.Memory), int(config.Parallelism), int(config.KeyLength))
	case "sha256":
		hasher := sha256.New()
		hasher.Write(data)
		hash = hasher.Sum(nil)
	default:
		return "", fmt.Errorf("unsupported hashing algorithm")
	}

	return hex.EncodeToString(hash), nil
}

func blockData(block *common.Block) []byte {
	blockInfo := fmt.Sprintf("%d%s%d", block.Timestamp, block.PrevBlockHash, block.Nonce)
	return []byte(blockInfo + concatTransactions(block.Transactions))
}

func concatTransactions(transactions []*common.Transaction) string {
	result := ""
	for _, tx := range transactions {
		result += tx.Signature // Simplified
	}
	return result
}

func ValidateBlock(block *common.Block, config *MinerConfig) (bool, error) {
	hash, err := CalculateHash(block, config)
	if err != nil {
		return false, err
	}

	return isHashValid(hash, block.Nonce), nil
}

func isHashValid(hash string, difficulty int) bool {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-difficulty))

	hexHash, _ := hex.DecodeString(hash)
	hashInt := new(big.Int).SetBytes(hexHash)

	return hashInt.Cmp(target) == -1
}

func MineBlock(transactions []*common.Transaction, prevHash string, config *MinerConfig, difficulty int) (*common.Block, error) {
	block := &common.Block{
		Timestamp:    time.Now().Unix(),
		Transactions: transactions,
		PrevBlockHash: prevHash,
		Difficulty:   difficulty,
	}

	NonceLimit := uint64(1<<32) // Example nonce limit
	for nonce := uint64(0); nonce < NonceLimit; nonce++ {
		block.Nonce = int(nonce)
		valid, err := ValidateBlock(block, config)
		if err != nil {
			return nil, err
		}
		if valid {
			return block, nil
		}
	}

	return nil, fmt.Errorf("failed to mine a new block after trying %d nonces", NonceLimit)
}

// Function to dynamically adjust the hashing algorithm based on system performance and energy consumption
func (sai *SustainabilityAndIncentives) AdjustHashingAlgorithm() {
	// Example: Adjust algorithm based on system performance metrics
	if sai.Blockchain.IsEnergyUsageHigh() {
		sai.Blockchain.MinerConfig.Algorithm = "scrypt" // Switch to Scrypt if energy usage is high
	} else {
		sai.Blockchain.MinerConfig.Algorithm = "argon2" // Default to Argon2
	}
}
