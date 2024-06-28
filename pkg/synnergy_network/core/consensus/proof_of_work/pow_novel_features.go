package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"synnergy_network_blockchain/pkg/synnergy_network/core/common"
)

// NovelFeatures encapsulates advanced features in the PoW consensus mechanism
type NovelFeatures struct {
	Blockchain *common.Blockchain
	lock       sync.RWMutex
}

// NewNovelFeatures initializes the structure with a blockchain reference
func NewNovelFeatures(blockchain *common.Blockchain) *NovelFeatures {
	return &NovelFeatures{
		Blockchain: blockchain,
	}
}

// IntroduceDynamicHashing dynamically adjusts the hashing difficulty to maintain network stability
func (nf *NovelFeatures) IntroduceDynamicHashing(transactions []*common.Transaction, previousHash string) (*common.Block, error) {
	nf.lock.Lock()
	defer nf.lock.Unlock()

	block := &common.Block{
		Timestamp:    time.Now().UnixNano(),
		Transactions: transactions,
		PrevBlockHash: previousHash,
		Nonce:        0,
	}

	target := nf.calculateDynamicTarget()
	var hashInt big.Int
	var hash [32]byte

	for {
		data := nf.PrepareData(block, nf.Blockchain.Difficulty)
		hash = sha256.Sum256(data)
		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(target) == -1 {
			block.Hash = hex.EncodeToString(hash[:])
			break
		} else {
			block.Nonce++
		}
	}

	nf.Blockchain.Blocks = append(nf.Blockchain.Blocks, block)
	return block, nil
}

// calculateDynamicTarget adjusts the mining target based on the current network conditions
func (nf *NovelFeatures) calculateDynamicTarget() *big.Int {
	nf.lock.RLock()
	defer nf.lock.RUnlock()

	currentDifficulty := nf.Blockchain.Difficulty
	return new(big.Int).Lsh(big.NewInt(1), uint(256-currentDifficulty))
}

// EcoFriendlyMining integrates sustainable mining practices
func (nf *NovelFeatures) EcoFriendlyMining(block *common.Block) error {
	// Implement logic to verify and reward eco-friendly mining practices
	return nil
}

// RewardAdjustmentForSustainability manages block rewards to promote long-term economic and environmental sustainability
func (nf *NovelFeatures) RewardAdjustmentForSustainability(block *common.Block) {
	nf.lock.Lock()
	defer nf.lock.Unlock()

	// Adjust reward based on halving and sustainability metrics
	halvingInterval := 210000
	totalBlocks := len(nf.Blockchain.Blocks)

	if totalBlocks % halvingInterval == 0 {
		halfReward := new(big.Int).Div(nf.Blockchain.Reward, big.NewInt(2))
		nf.Blockchain.Reward.Set(halfReward)
	}
}

// ImplementAdvancedSecurityFeatures enhances security measures in the mining process
func (nf *NovelFeatures) ImplementAdvancedSecurityFeatures(block *common.Block) error {
	// Add implementations for advanced security features
	return nil
}

// PrepareData prepares the combined block data for hashing, integrating advanced security features
func (nf *NovelFeatures) PrepareData(block *common.Block, difficulty int) []byte {
	data := []byte(fmt.Sprintf("%d-%s-%s-%d", block.Timestamp, block.PrevBlockHash, nf.transactionData(block.Transactions), block.Nonce))
	// Include additional security data or metadata
	return data
}

// transactionData compiles transaction data into a single byte slice
func (nf *NovelFeatures) transactionData(transactions []*common.Transaction) string {
	var txData strings.Builder
	for _, tx := range transactions {
		txData.WriteString(hex.EncodeToString(tx.Signature)) // Convert []byte to hex string before concatenation
	}
	return txData.String()
}

// RealTimeFraudDetection implements mechanisms to detect and prevent fraudulent activities in real-time
func (nf *NovelFeatures) RealTimeFraudDetection(transaction *common.Transaction) bool {
	// Logic to detect fraudulent transactions
	return true // Placeholder for actual implementation
}
