package proof_of_work

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// MiningAlgorithm encapsulates the proof of work process and advanced parameters.
type MiningAlgorithm struct {
	blockReward          float64
	rewardHalvingInterval int
	maxHalvings          int
	difficulty           uint32
	adjustmentInterval   int
	mutex                sync.RWMutex
	// New fields to optimize and secure mining operations
	lastBlockTime       time.Time
	averageBlockTime    time.Duration
	minerConvergence    []float64
	hashRateAdjustments []time.Duration
}

// NewMiningAlgorithm initializes the mining algorithm with default parameters.
func NewMiningAlgorithm() *MiningAlgorithm {
	return &MiningAlgorithm{
		blockReward:          1252,
		rewardHalvingInterval: 200000,
		maxHalvings:          64,
		difficulty:           1,
		adjustmentInterval:   2016,
		lastBlockTime:        time.Now(),
		averageBlockTime:     10 * time.Minute,
		minerConvergence:     make([]float64, 0),
		hashRateAdjustments:  make([]time.Duration, 0),
	}
}

// CalculateHash computes a hash using Argon2, incorporating a dynamic salt for added security.
func (m *MiningAlgorithm) CalculateHash(data string, nonce uint64) string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Dynamic salt generation using current time to prevent rainbow table attacks
	timeSalt := make([]byte, 8)
	binary.LittleEndian.PutUint64(timeSalt, uint64(time.Now().UnixNano()))
	seed := data + string(timeSalt) + strconv.FormatUint(nonce, 10)

	hash := argon2.IDKey([]byte(seed), timeSalt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

// MineBlock performs the mining operation by finding the correct nonce, adjusting for dynamic difficulty.
func (m *MiningAlgorithm) MineBlock(data string, target string) (uint64, string, error) {
	var nonce uint64 = 0
	for {
		hash := m.CalculateHash(data, nonce)
		if strings.HasPrefix(hash, target) {
			m.recordBlockTime()
			return nonce, hash, nil
		}
		nonce++
		if nonce == ^uint64(0) { // If nonce wraps around, exit loop
			return 0, "", errors.New("nonce overflow, mining failed")
		}
	}
}

// recordBlockTime updates the timing metrics after a block is mined.
func (m *MiningAlgorithm) recordBlockTime() {
	now := time.Now()
	m.mutex.Lock()
	blockDuration := now.Sub(m.lastBlockTime)
	m.lastBlockTime = now
	m.averageBlockTime = (m.averageBlockTime + blockDuration) / 2
	m.hashRateAdjustments = append(m.hashRateAdjustments, blockDuration)
	m.mutex.Unlock()

	// Post-mining difficulty adjustment based on time taken to mine the latest block
	m.AdjustDifficulty(blockDuration, m.averageBlockTime)
}

// CalculateReward computes the block reward with halving consideration.
func (m *MiningAlgorithm) CalculateReward(currentHeight int) float64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	halvings := currentHeight / m.rewardHalvingInterval
	if halvings > m.maxHalvings {
		return 0
	}
	return m.blockReward / float64(uint(1)<<uint(halvings))
}

// AdjustDifficulty dynamically adjusts the mining difficulty based on block generation rate.
func (m *MiningAlgorithm) AdjustDifficulty(actualTime, expectedTime time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	ratio := float64(actualTime) / float64(expectedTime)
	if ratio < 0.9 {
		m.difficulty++
	} else if ratio > 1.1 && m.difficulty > 1 {
		m.difficulty--
	}
}

// GetCurrentDifficulty provides safe access to the current difficulty.
func (m *MiningAlgorithm) GetCurrentDifficulty() uint32 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.difficulty
}

// GenerateDifficultyTarget creates a mining target based on the current difficulty.
func (m *MiningAlgorithm) GenerateDifficultyTarget() string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	leadingZeros := int(m.difficulty)
	return strings.Repeat("0", leadingZeros) + strings.Repeat("f", 64-leadingZeros)
}

// SecurityMeasures to protect the mining process and maintain blockchain integrity.
func (m *MiningAlgorithm) SecurityMeasures() {
	// Implement cryptographic signature verifications, consensus checks, and random audits
}

// ExtendCompatibility allows the algorithm to adapt to technological advancements.
func (m *MiningAlgorithm) ExtendCompatibility() {
	// Update mining parameters based on ongoing network evaluations and consensus decisions
}
