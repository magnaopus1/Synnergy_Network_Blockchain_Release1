package security

import (
	"log"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

const (
	Salt      = "unique-salt-security"
	KeyLength = 32
	// Threshold percentage that triggers an alert for potential 51% attack
	AttackThreshold = 50.0
)

// Block represents a block in the blockchain
type Block struct {
	Timestamp    time.Time
	MinerAddress string
}

// MinerStatistics keeps track of mining statistics for individual miners
type MinerStatistics struct {
	Address       string
	BlocksMined   int
	PercentageOfTotal float64
}

// AttackDetectionSystem monitors and detects 51% attacks
type AttackDetectionSystem struct {
	minerStats map[string]*MinerStatistics
	totalBlocks int
}

// NewAttackDetectionSystem initializes a new attack detection system
func NewAttackDetectionSystem() *AttackDetectionSystem {
	return &AttackDetectionSystem{
		minerStats: make(map[string]*MinerStatistics),
		totalBlocks: 0,
	}
}

// AddBlock records a new block to the mining statistics
func (ads *AttackDetectionSystem) AddBlock(block Block) {
	stats, exists := ads.minerStats[block.MinerAddress]
	if !exists {
		stats = &MinerStatistics{Address: block.MinerAddress}
		ads.minerStats[block.MinerAddress] = stats
	}
	stats.BlocksMined++
	ads.totalBlocks++
	ads.recalculatePercentages()
}

// recalculatePercentages updates the mining percentages for all miners
func (ads *AttackDetectionSystem) recalculatePercentages() {
	for _, stats := range ads.minerStats {
		stats.PercentageOfTotal = (float64(stats.BlocksMined) / float64(ads.totalBlocks)) * 100.0
		if stats.PercentageOfTotal > AttackThreshold {
			ads.respondToAttack(stats)
		}
	}
}

// respondToAttack triggers actions in response to a detected 51% attack
func (ads *AttackDetectionSystem) respondToAttack(stats *MinerStatistics) {
	log.Printf("WARNING: Potential 51%% Attack Detected. Miner %s controls %.2f%% of the network.", stats.Address, stats.PercentageOfTotal)
	// Additional mitigation strategies could be implemented here
}

// EncryptData handles data encryption using Argon2
func EncryptData(data []byte) []byte {
	salt := []byte(Salt)
	return argon2.IDKey(data, salt, 1, 64*1024, 4, KeyLength)
}

// DecryptData handles data decryption using Scrypt
func DecryptData(data []byte) ([]byte, error) {
	key, err := scrypt.Key(data, []byte(Salt), 16384, 8, 1, KeyLength)
	if err != nil {
		log.Println("Error decrypting data:", err)
		return nil, err
	}
	return key, nil
}

func main() {
	detector := NewAttackDetectionSystem()
	// Simulate block additions
	detector.AddBlock(Block{Timestamp: time.Now(), MinerAddress: "Miner1"})
	detector.AddBlock(Block{Timestamp: time.Now(), MinerAddress: "Miner2"})
	detector.AddBlock(Block{Timestamp: time.Now(), MinerAddress: "Miner1"})
	detector.AddBlock(Block{Timestamp: time.Now(), MinerAddress: "Miner1"})
}
