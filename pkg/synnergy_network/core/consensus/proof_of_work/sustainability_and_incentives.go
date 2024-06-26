package proof_of_work

import (
    "crypto/rand"
    "encoding/hex"
    "math/big"
    "sync"
    "time"
    "log"
    
    "golang.org/x/crypto/argon2"
)

type SustainabilityIncentives struct {
    blockchain        *Blockchain
    rewardHalvingRate int
    maxHalvings       int
    blockReward       float64
    halvingCounter    int
    sync.Mutex
}

// NewSustainabilityIncentives initializes the module with default parameters and blockchain reference
func NewSustainabilityIncentives(blockchain *Blockchain) *SustainabilityIncentives {
    return &SustainabilityIncentives{
        blockchain:        blockchain,
        rewardHalvingRate: 200000,
        maxHalvings:       10, // Adjusted for real-world application
        blockReward:       1252, // Initial block reward in SYN tokens
        halvingCounter:    0,
    }
}

// CalculateReward adjusts the mining reward based on block height
func (si *SustainabilityIncentives) CalculateReward() float64 {
    si.Lock()
    defer si.Unlock()

    blocksMined := len(si.blockchain.Chain)
    halvings := blocksMined / si.rewardHalvingRate

    if halvings > si.maxHalvings {
        return 0 // No reward if max halvings reached
    }

    // Adjust reward and increment halving counter if threshold reached
    if blocksMined%si.rewardHalvingRate == 0 && blocksMined > 0 {
        si.blockReward /= 2
        si.halvingCounter++
        log.Printf("Reward halved to %f SYN after %d blocks", si.blockReward, blocksMined)
    }

    return si.blockReward
}

// MonitorNetworkHealth checks for network stability and adjusts difficulty as needed
func (si *SustainabilityIncentives) MonitorNetworkHealth() {
    ticker := time.NewTicker(time.Minute * 10) // Check every 10 minutes
    defer ticker.Stop()

    for range ticker.C {
        if len(si.blockchain.Chain) < 2 {
            continue
        }

        lastBlockTime := si.blockchain.Chain[len(si.blockchain.Chain)-1].Timestamp
        timeSinceLastBlock := time.Since(lastBlockTime)

        // Simplified example: Adjust difficulty if time since last block is too high or low
        if timeSinceLastBlock < time.Minute*8 { // Less than target time, increase difficulty
            si.blockchain.Difficulty++
        } else if timeSinceLastBlock > time.Minute*12 { // More than target time, decrease difficulty
            si.blockchain.Difficulty--
        }

        log.Printf("Difficulty adjusted to %d due to mining time variations", si.blockchain.Difficulty)
    }
}

// Implement additional functions to support energy-efficient mining practices and further enhance security measures
