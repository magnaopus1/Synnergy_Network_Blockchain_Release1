package consensus

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "math/big"
    "time"
    "synthron-blockchain/pkg/synnergy_network/core/common"
)

// DifficultyManager manages the adjustment of mining difficulty.
type DifficultyManager struct {
    CurrentDifficulty *big.Int
    TargetBlockTime   time.Duration
    LastAdjustment    time.Time
}

// NewDifficultyManager initializes the difficulty manager with a predefined difficulty.
func NewDifficultyManager(initialDifficulty *big.Int) *DifficultyManager {
    return &DifficultyManager{
        CurrentDifficulty: initialDifficulty,
        TargetBlockTime:   10 * time.Minute, // Default target block time.
        LastAdjustment:    time.Now(),
    }
}

// CalculateNewDifficulty adjusts the difficulty based on the actual time taken to mine the last 2016 blocks.
func (dm *DifficultyManager) CalculateNewDifficulty(actualTime, expectedTime time.Duration) {
    ratio := float64(actualTime) / float64(expectedTime)
    newDifficulty := float64(dm.CurrentDifficulty.Int64()) * ratio

    // Apply dampening to avoid drastic changes in difficulty.
    dampeningFactor := 0.25
    newDifficulty = (newDifficulty * (1 - dampeningFactor)) + (float64(dm.CurrentDifficulty.Int64()) * dampeningFactor)

    // Set the new difficulty with bounds check
    if newDifficulty < 1 {
        newDifficulty = 1
    }
    dm.CurrentDifficulty = big.NewInt(int64(newDifficulty))
    dm.LastAdjustment = time.Now()
}

// AdjustDifficulty dynamically adjusts difficulty every 2016 blocks.
func (dm *DifficultyManager) AdjustDifficulty(blocks []common.Block) {
    if len(blocks) < 2016 {
        return // Not enough blocks to adjust, wait for more blocks.
    }

    // Calculate the actual time for the last 2016 blocks.
    actualTime := time.Duration(blocks[len(blocks)-1].Timestamp-blocks[0].Timestamp) * time.Second
    expectedTime := dm.TargetBlockTime * 2016

    dm.CalculateNewDifficulty(actualTime, expectedTime)
}

// SimulateBlockMining simulates the mining of blocks and adjusts difficulty based on the simulation.
func (dm *DifficultyManager) SimulateBlockMining() {
    var blocks []common.Block
    for i := 0; i < 2016; i++ {
        block := dm.MineBlock()
        blocks = append(blocks, block)
    }
    dm.AdjustDifficulty(blocks)
}

// MineBlock simulates the mining of a single block, incorporating the current difficulty into the nonce calculation.
func (dm *DifficultyManager) MineBlock() common.Block {
    nonce := 0
    for {
        hash := calculateHashWithNonce(nonce, dm.CurrentDifficulty)
        if hash[:len("0000")] == "0000" { // Simplified difficulty check, real implementation may vary
            break
        }
        nonce++
    }
    return common.Block{
        Timestamp: time.Now().Unix(),
        Nonce:     nonce,
    }
}

// calculateHashWithNonce simulates a hash calculation for the block mining process.
func calculateHashWithNonce(nonce int, difficulty *big.Int) string {
    data := fmt.Sprintf("%d:%s", nonce, difficulty.String())
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}
