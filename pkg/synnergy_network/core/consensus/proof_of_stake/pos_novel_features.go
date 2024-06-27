package consensus

import (
    "crypto/rand"
    "math/big"
    "time"
    "fmt"
)

// NovelFeatures encapsulates new and innovative features for PoS
type NovelFeatures struct {
    CommunityIncentives map[string]*IncentiveDetail
    SecurityEnhancements *SecurityFeatures
}

// IncentiveDetail defines the structure for holding incentive data
type IncentiveDetail struct {
    Description string
    Active      bool
    RewardMultiplier float64
}

// SecurityFeatures encapsulates security enhancements in the PoS mechanism
type SecurityFeatures struct {
    Argon2Parameters *Argon2Params
}

// Argon2Params holds the parameters for the Argon2 hashing algorithm
type Argon2Params struct {
    Memory      uint32
    Iterations  uint32
    Parallelism uint8
}

// NewNovelFeatures initializes the novel features with default settings
func NewNovelFeatures() *NovelFeatures {
    return &NovelFeatures{
        CommunityIncentives: make(map[string]*IncentiveDetail),
        SecurityEnhancements: &SecurityFeatures{
            Argon2Parameters: &Argon2Params{
                Memory:      64 * 1024,
                Iterations:  3,
                Parallelism: 2,
            },
        },
    }
}

// AddIncentive adds a new incentive to the blockchain
func (nf *NovelFeatures) AddIncentive(id, description string, multiplier float64) {
    nf.CommunityIncentives[id] = &IncentiveDetail{
        Description: description,
        Active: true,
        RewardMultiplier: multiplier,
    }
}

// ActivateIncentive toggles the active status of an incentive
func (nf *NovelFeatures) ActivateIncentive(id string, activate bool) error {
    incentive, exists := nf.CommunityIncentives[id]
    if !exists {
        return fmt.Errorf("incentive not found")
    }
    incentive.Active = activate
    return nil
}

// CalculateRewardAdjustment calculates adjusted rewards based on incentives
func (nf *NovelFeatures) CalculateRewardAdjustment(incentiveID string, baseReward *big.Int) (*big.Int, error) {
    incentive, exists := nf.CommunityIncentives[incentiveID]
    if !exists || !incentive.Active {
        return baseReward, fmt.Errorf("inactive or non-existing incentive")
    }
    multiplier := big.NewFloat(incentive.RewardMultiplier)
    reward := new(big.Float).SetInt(baseReward)
    newReward := new(big.Float).Mul(reward, multiplier)
    result := new(big.Int)
    newReward.Int(result)
    return result, nil
}

// RandomizeSelection uses cryptographic randomness to select validators
func (nf *NovelFeatures) RandomizeSelection(candidateIDs []string) (string, error) {
    if len(candidateIDs) == 0 {
        return "", fmt.Errorf("no candidates available")
    }
    idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(candidateIDs))))
    if err != nil {
        return "", err
    }
    return candidateIDs[idx.Int64()], nil
}
