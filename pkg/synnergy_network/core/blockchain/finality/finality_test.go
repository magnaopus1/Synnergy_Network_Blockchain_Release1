package finality

import (
	"testing"
	"time"

	"github.com/synnergy_network/consensus"
	"github.com/synnergy_network/crypto"
	"github.com/synnergy_network/types"
	"github.com/stretchr/testify/assert"
)

func TestFinalityManager(t *testing.T) {
	consensusEngine := &consensus.Engine{}
	thresholds := FinalityThresholds{
		ConfirmationDepth: 5,
		DynamicThresholds: true,
	}
	finalityManager := NewFinalityManager(consensusEngine, true, thresholds)

	validator := Validator{
		ID:         "validator1",
		PublicKey:  "public_key",
		PrivateKey: "private_key",
	}

	finalityManager.RegisterValidator(validator)
	blockHash := "block_hash_example"
	finalizedBlock, err := finalityManager.CreateFinalizedBlock(blockHash, validator.ID)

	assert.NoError(t, err, "Error creating finalized block")
	assert.NotEmpty(t, finalizedBlock.BlockHash, "Finalized block hash should not be empty")

	isFinalized, err := finalityManager.IsBlockFinalized(blockHash)
	assert.NoError(t, err, "Error checking if block is finalized")
	assert.True(t, isFinalized, "Block should be finalized")

	isValid, err := finalityManager.ValidateFinalizedBlock(finalizedBlock)
	assert.NoError(t, err, "Error validating finalized block")
	assert.True(t, isValid, "Finalized block should be valid")
}

func TestDynamicThresholds(t *testing.T) {
	consensusEngine := &consensus.Engine{}
	thresholds := FinalityThresholds{
		ConfirmationDepth: 5,
		DynamicThresholds: true,
	}
	finalityManager := NewFinalityManager(consensusEngine, true, thresholds)

	networkConditions := NetworkConditions{
		CongestionLevel: 90,
	}
	finalityManager.ApplyDynamicThresholds(networkConditions)

	assert.Equal(t, 6, finalityManager.finalityThresholds.ConfirmationDepth, "Confirmation depth should increase to 6")

	networkConditions.CongestionLevel = 10
	finalityManager.ApplyDynamicThresholds(networkConditions)

	assert.Equal(t, 5, finalityManager.finalityThresholds.ConfirmationDepth, "Confirmation depth should decrease to 5")
}

func TestGetFinalizedBlockMetrics(t *testing.T) {
	consensusEngine := &consensus.Engine{}
	thresholds := FinalityThresholds{
		ConfirmationDepth: 5,
		DynamicThresholds: true,
	}
	finalityManager := NewFinalityManager(consensusEngine, true, thresholds)

	validator := Validator{
		ID:         "validator1",
		PublicKey:  "public_key",
		PrivateKey: "private_key",
	}

	finalityManager.RegisterValidator(validator)
	blockHash := "block_hash_example"
	finalityManager.CreateFinalizedBlock(blockHash, validator.ID)

	metrics := finalityManager.GetFinalizedBlockMetrics()

	assert.NotEmpty(t, metrics["finalized_blocks"], "Metrics should include finalized_blocks")
	assert.NotEmpty(t, metrics["validators"], "Metrics should include validators")
	assert.NotEmpty(t, metrics["last_finalized_time"], "Metrics should include last_finalized_time")
}
