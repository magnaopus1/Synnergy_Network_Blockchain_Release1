package proof_of_stake

import (
	"crypto/sha256"
	"math/big"
	"time"

	"github.com/synthron/synthronchain/crypto/vrf"
	"github.com/synthron/synthronchain/storage"
)

// Validator represents a node that can be selected to validate transactions
type Validator struct {
	Address        string
	Stake          *big.Int
	ActiveSince    time.Time
	IsSlashed      bool
	LastActive     time.Time
	LockUpPeriod   time.Duration
	VRFProof       []byte
}

// Blockchain represents the state of the blockchain including all validators
type Blockchain struct {
	Validators []*Validator
	LatestBlockHash []byte
}

// NewBlockchain initializes a new blockchain with a set of validators
func NewBlockchain(validators []*Validator, latestBlockHash []byte) *Blockchain {
	return &Blockchain{
		Validators:     validators,
		LatestBlockHash: latestBlockHash,
	}
}

// SelectValidators selects a subset of validators for the next block creation based on VRF
func (bc *Blockchain) SelectValidators() ([]*Validator, error) {
	selectedValidators := []*Validator{}
	for _, v := range bc.Validators {
		if v.IsSlashed {
			continue
		}
		if bc.isEligibleForSelection(v) {
			selectedValidators = append(selectedValidators, v)
		}
	}
	return selectedValidators, nil
}

// isEligibleForSelection checks if a validator's VRF proof is valid for the next block
func (bc *Blockchain) isEligibleForSelection(validator *Validator) bool {
	// Generate VRF seed from the latest block hash and current timestamp to ensure unpredictability
	seed := generateSeed(bc.LatestBlockHash, time.Now().UnixNano())
	threshold := calculateSelectionThreshold(validator.Stake)
	return vrf.Verify(validator.Address, seed, validator.VRFProof, threshold)
}

// generateSeed generates a new seed for VRF based on the last block hash and current time
func generateSeed(lastBlockHash []byte, timestamp int64) []byte {
	hash := sha256.New()
	hash.Write(lastBlockHash)
	hash.Write(big.NewInt(timestamp).Bytes())
	return hash.Sum(nil)
}

// calculateSelectionThreshold calculates the threshold for a validator to be selected
func calculateSelectionThreshold(stake *big.Int) *big.Int {
	// Assuming the threshold scales with the amount of stake to increase the chance of high stakers
	return new(big.Int).Mul(stake, big.NewInt(1000)) // Simplified scaling factor
}

// Simulate adding validators and selecting them for block validation
func main() {
	validators := []*Validator{
		{
			Address:      "0xABC123",
			Stake:        big.NewInt(1000),
			ActiveSince:  time.Now(),
			IsSlashed:    false,
			LastActive:   time.Now(),
			LockUpPeriod: 90 * 24 * time.Hour,
		},
		// Additional validators would be added here
	}

	// Assume a block hash for the sake of this simulation
	latestBlockHash := sha256.Sum256([]byte("previous block hash"))
	blockchain := NewBlockchain(validators, latestBlockHash[:])

	// Select validators for the next block
	selectedValidators, err := blockchain.SelectValidators()
	if err != nil {
		panic(err)
	}

	for _, v := range selectedValidators {
		println("Selected Validator:", v.Address)
	}
}
