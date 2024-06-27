package hybrid

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/synnergy_network/core/consensus/proof_of_history"
	"github.com/synnergy_network/core/consensus/proof_of_stake"
	"github.com/synnergy_network/core/consensus/proof_of_work"
	"golang.org/x/crypto/argon2"
)

// Constants for consensus mechanisms
const (
	PoW = "PoW"
	PoS = "PoS"
	PoH = "PoH"
)

// HybridConsensus manages the integration and transition between PoW, PoH, and PoS.
type HybridConsensus struct {
	PoWConsensus  *proof_of_work.Consensus
	PoHConsensus  *proof_of_history.Consensus
	PoSConsensus  *proof_of_stake.Consensus
	CurrentMethod string
}

// NewHybridConsensus initializes the hybrid consensus mechanism.
func NewHybridConsensus() *HybridConsensus {
	return &HybridConsensus{
		PoWConsensus:  proof_of_work.NewConsensus(),
		PoHConsensus:  proof_of_history.NewConsensus(),
		PoSConsensus:  proof_of_stake.NewConsensus(),
		CurrentMethod: PoW, // Default to PoW
	}
}

// TransitionConsensus transitions between consensus mechanisms based on network conditions.
func (hc *HybridConsensus) TransitionConsensus(networkLoad int, securityThreat bool, stakeConcentration float64) {
	threshold := hc.calculateThreshold(networkLoad, stakeConcentration)

	if securityThreat || threshold > 0.7 {
		hc.CurrentMethod = PoW
	} else if networkLoad > 1000 {
		hc.CurrentMethod = PoH
	} else {
		hc.CurrentMethod = PoS
	}
}

// calculateThreshold calculates the threshold for consensus switching.
func (hc *HybridConsensus) calculateThreshold(networkLoad int, stakeConcentration float64) float64 {
	alpha := 0.5
	beta := 0.5
	return alpha*float64(networkLoad) + beta*stakeConcentration
}

// MineBlock mines a block using the current consensus method.
func (hc *HybridConsensus) MineBlock(data string) (*proof_of_work.Block, error) {
	switch hc.CurrentMethod {
	case PoW:
		return hc.PoWConsensus.MineBlock(data)
	case PoH:
		hash, err := hc.PoHConsensus.CreatePoH(data)
		if err != nil {
			return nil, err
		}
		return &proof_of_work.Block{
			Data: data,
			Hash: hash,
		}, nil
	case PoS:
		return hc.PoSConsensus.MineBlock(data)
	default:
		return nil, errors.New("unsupported consensus method")
	}
}

// AddBlock adds a block to the blockchain using the current consensus method.
func (hc *HybridConsensus) AddBlock(block *proof_of_work.Block) error {
	switch hc.CurrentMethod {
	case PoW:
		return hc.PoWConsensus.AddBlock(block)
	case PoH:
		return hc.PoHConsensus.AddBlock(block)
	case PoS:
		return hc.PoSConsensus.AddBlock(block)
	default:
		return errors.New("unsupported consensus method")
	}
}

// ValidateBlock validates a block using the current consensus method.
func (hc *HybridConsensus) ValidateBlock(validatorID string, block *proof_of_work.Block) error {
	switch hc.CurrentMethod {
	case PoS:
		return hc.PoSConsensus.ValidateBlock(validatorID, block)
	default:
		return errors.New("validation is only supported for PoS in this context")
	}
}

// SlashValidator slashes a validator for malicious behavior.
func (hc *HybridConsensus) SlashValidator(validatorID string) error {
	if hc.CurrentMethod == PoS {
		return hc.PoSConsensus.SlashValidator(validatorID)
	}
	return errors.New("slashing is only supported for PoS in this context")
}

// Example usage of Argon2 mining in PoW phase
func (hc *HybridConsensus) MineWithArgon2(data string) (*proof_of_work.Block, error) {
	if hc.CurrentMethod != PoW {
		return nil, errors.New("current method is not PoW")
	}

	prevBlock := hc.PoWConsensus.Blockchain.Blocks[len(hc.PoWConsensus.Blockchain.Blocks)-1]
	newBlock := proof_of_work.NewBlock(data, prevBlock)
	salt := []byte("random_salt")

	for !proof_of_work.IsHashValid(fmt.Sprintf("%x", argon2.IDKey([]byte(newBlock.Data), salt, 1, 64*1024, 4, 32))) {
		newBlock.Nonce++
		newBlock.Hash = fmt.Sprintf("%x", argon2.IDKey([]byte(newBlock.Data), salt, 1, 64*1024, 4, 32))
	}

	hc.PoWConsensus.Blockchain.AddBlock(newBlock)
	return newBlock, nil
}
add other mining methods to switch too incase slow such as sha-256, scrypt , sha-3, aes