package proof_of_work

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Enhanced types to support richer features and better security
type Block struct {
	PreviousHash string
	Timestamp    time.Time
	Data         string
	Nonce        uint64
	Hash         string
	Transactions []Transaction
}

type Blockchain struct {
	Chain               []Block
	Difficulty          uint32
	DifficultyAdjustmentInterval int
}

type Transaction struct {
	Sender    string
	Recipient string
	Amount    float64
	Fee       float64
	Signature string
}

type MiningProcess struct {
	Blockchain        *Blockchain
	BlockReward       float64
	RewardHalvingRate int
	MaxHalvings       int
	sync.RWMutex
}

// Initializes with default or provided parameters, ready for flexible configurations
func NewMiningProcess(blockchain *Blockchain, reward float64, halvingRate, maxHalvings int) *MiningProcess {
	return &MiningProcess{
		Blockchain:        blockchain,
		BlockReward:       reward,
		RewardHalvingRate: halvingRate,
		MaxHalvings:       maxHalvings,
	}
}

// Mining and block generation logic enhanced for performance and security
func (mp *MiningProcess) CreateBlock(previousHash string, transactions []Transaction) Block {
	mp.Lock()
	defer mp.Unlock()

	nonce := uint64(0)
	var block Block
	for {
		block = Block{
			Timestamp:    time.Now(),
			PreviousHash: previousHash,
			Nonce:        nonce,
			Transactions: transactions,
		}
		block.Hash = mp.CalculateBlockHash(block)
		if mp.IsValidHash(block.Hash) {
			break
		}
		nonce++
	}

	mp.Blockchain.Chain = append(mp.Blockchain.Chain, block)
	return block
}

func (mp *MiningProcess) CalculateBlockHash(block Block) string {
	data := block.PreviousHash + block.Timestamp.String() + strconv.FormatUint(block.Nonce, 10)
	for _, tx := range block.Transactions {
		data += tx.String()
	}
	hash := argon2.IDKey([]byte(data), []byte("synthron_salt"), 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

func (mp *MiningProcess) IsValidHash(hash string) bool {
	target := mp.GetDifficultyTarget()
	return strings.HasPrefix(hash, target)
}

func (mp *MiningProcess) GetDifficultyTarget() string {
	difficultyBits := int(mp.Blockchain.Difficulty)
	return strings.Repeat("0", difficultyBits) + strings.Repeat("f", 64-difficultyBits)
}

// Reward and difficulty adjustment mechanics optimized for economic sustainability
func (mp *MiningProcess) CalculateMiningReward(height int) float64 {
	halvings := height / mp.RewardHalvingRate
	if halvings > mp.MaxHalvings {
		return 0
	}
	return mp.BlockReward / float64(1<<uint(halvings))
}

func (mp *MiningProcess) AdjustDifficulty(actualTime, expectedTime time.Duration) {
	mp.Lock()
	defer mp.Unlock()

	ratio := float64(actualTime) / float64(expectedTime)
	if ratio < 0.9 {
		mp.Blockchain.Difficulty++
	} else if ratio > 1.1 && mp.Blockchain.Difficulty > 1 {
		mp.Blockchain.Difficulty--
	}
}

// MonitorMiningEfficiency should be run in a separate goroutine to continuously monitor the mining process.
func (mp *MiningProcess) MonitorMiningEfficiency() {
	expectedBlockTime := time.Minute * 10 // Expected time to mine one block
	ticker := time.NewTicker(time.Minute * 5) // Check every 5 minutes

	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if len(mp.Blockchain.Chain) < 2 {
				continue
			}

			lastBlock := mp.Blockchain.Chain[len(mp.Blockchain.Chain)-1]
			secondLastBlock := mp.Blockchain.Chain[len(mp.Blockchain.Chain)-2]

			actualTime := lastBlock.Timestamp.Sub(secondLastBlock.Timestamp)
			mp.AdjustDifficulty(actualTime, expectedBlockTime)

			log.Printf("Adjusted difficulty to %d due to mining time variation", mp.Blockchain.Difficulty)
		}
	}
}

func main() {
	// Initialize blockchain with genesis block
	genesisBlock := Block{
		PreviousHash: "0",
		Timestamp:    time.Now(),
		Data:         "Genesis Block",
		Nonce:        0,
	}
	genesisBlock.Hash = hex.EncodeToString(argon2.IDKey([]byte(genesisBlock.Data), []byte("genesis_salt"), 1, 64*1024, 4, 32))

	blockchain := &Blockchain{
		Chain:               []Block{genesisBlock},
		Difficulty:          20, // Starting difficulty, relatively low for demonstration
		DifficultyAdjustmentInterval: 2016,
	}

	// Set up the mining process
	miner := NewMiningProcess(blockchain, 1252, 200000, 64)
	go miner.MonitorMiningEfficiency() // Start monitoring in a separate goroutine

	// Example of mining blocks
	for i := 0; i < 10; i++ {
		lastBlock := blockchain.Chain[len(blockchain.Chain)-1]
		newBlock, err := miner.MineBlock()
		if err != nil {
			log.Fatalf("Mining failed: %s", err)
		}
		log.Printf("New block mined with hash: %s at height: %d", newBlock.Hash, len(blockchain.Chain))
	}

	// The mining will run indefinitely unless there is a break condition or stop signal handled elsewhere.
}