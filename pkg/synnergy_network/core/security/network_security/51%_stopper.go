package security

import (
	"log"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

const (
	Salt      = "unique-security-salt"
	KeyLength = 32
	Threshold = 50 // Percentage above which an attack is suspected
)

// Block represents a blockchain block
type Block struct {
	Timestamp    time.Time
	MinerAddress string
}

// MinerStats tracks mining statistics for each miner
type MinerStats struct {
	Address       string
	BlocksMined   int
	TotalBlocks   int
	MiningPercent float64
}

// AttackDetector manages the detection of a 51% attack
type AttackDetector struct {
	miners map[string]*MinerStats
}

// NewAttackDetector creates a new instance of AttackDetector
func NewAttackDetector() *AttackDetector {
	return &AttackDetector{
		miners: make(map[string]*MinerStats),
	}
}

// AddBlock processes a new block mined by a miner
func (ad *AttackDetector) AddBlock(b Block) {
	if stats, ok := ad.miners[b.MinerAddress]; ok {
		stats.BlocksMined++
	} else {
		ad.miners[b.MinerAddress] = &MinerStats{
			Address:     b.MinerAddress,
			BlocksMined: 1,
		}
	}
	ad.updateMiningPercentages()
}

// updateMiningPercentages recalculates the mining percentages for all miners
func (ad *AttackDetector) updateMiningPercentages() {
	totalBlocks := 0
	for _, stats := range ad.miners {
		totalBlocks += stats.BlocksMined
	}
	for _, stats := range ad.miners {
		stats.TotalBlocks = totalBlocks
		stats.MiningPercent = float64(stats.BlocksMined) / float64(totalBlocks) * 100
		if stats.MiningPercent > Threshold {
			ad.respondTo51PercentAttack(stats)
		}
	}
}

// respondTo51PercentAttack takes actions if a miner exceeds the threshold
func (ad *AttackDetector) respondTo51PercentAttack(stats *MinerStats) {
	log.Printf("Potential 51%% Attack Detected! Miner %s controls %f%% of the network.", stats.Address, stats.MiningPercent)
	// Implement response strategies such as reassigning mining difficulty, alerting network operators, or temporary suspension of miner
}

// EncryptData uses Argon2 for encryption
func EncryptData(data []byte) []byte {
	salt := []byte(Salt)
	return argon2.IDKey(data, salt, 1, 64*1024, 4, KeyLength)
}

// DecryptData uses Scrypt for decryption
func DecryptData(data []byte) ([]byte, error) {
	dk, err := scrypt.Key(data, []byte(Salt), 16384, 8, 1, KeyLength)
	if err != nil {
		log.Fatal("Decryption error:", err)
		return nil, err
	}
	return dk, nil
}

func main() {
	detector := NewAttackDetector()
	// Simulate block mining
	detector.AddBlock(Block{Timestamp: time.Now(), MinerAddress: "Miner1"})
	detector.AddBlock(Block{Timestamp: time.Now(), MinerAddress: "Miner2"})
	detector.AddBlock(Block{Timestamp: time.Now(), MinerAddress: "Miner1"})
	detector.AddBlock(Block{Timestamp: time.Now(), MinerAddress: "Miner1"})
}
