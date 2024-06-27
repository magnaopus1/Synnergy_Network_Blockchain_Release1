package consensus

import (
    "math/big"
    "testing"

    "synnergy_network/pkg/synnergy_network/core/blockchain"
    "github.com/stretchr/testify/assert"
)

// TestPoHTimestamping verifies the timestamping logic used in the PoH mechanism.
func TestPoHTimestamping(t *testing.T) {
    poh := NewPoH()
    transactions := []*blockchain.Transaction{
        blockchain.NewTransaction("tx1", "data1"),
        blockchain.NewTransaction("tx2", "data2"),
    }

    poh.ProcessTransactions(transactions)
    assert.NotEmpty(t, transactions[0].Timestamp, "The timestamp should be set.")
    assert.NotEmpty(t, transactions[1].Timestamp, "The timestamp should be set.")
    assert.NotEqual(t, transactions[0].Timestamp, transactions[1].Timestamp, "Each timestamp should be unique.")
}

// TestHashChainGeneration checks the integrity of the hash chain formed by transactions.
func TestHashChainGeneration(t *testing.T) {
    poh := NewPoH()
    transactions := []*blockchain.Transaction{
        blockchain.NewTransaction("tx1", "data1"),
        blockchain.NewTransaction("tx2", "data2"),
    }

    poh.ProcessTransactions(transactions)
    assert.NotEmpty(t, transactions[0].Hash, "The hash should not be empty.")
    assert.NotEmpty(t, transactions[1].Hash, "The hash should not be empty.")
    assert.NotEqual(t, transactions[0].Hash, transactions[1].Hash, "Each hash should be unique.")
    assert.Equal(t, transactions[1].PrevHash, transactions[0].Hash, "The hash chain should be continuous and ordered.")
}

// TestRewardCalculation validates the reward calculation mechanism within the PoH context.
func TestRewardCalculation(t *testing.T) {
    config := &RewardConfig{
        BaseReward:    big.NewInt(1000),
        TotalStake:    big.NewInt(10000),
        DynamicFactor: 1.5,
    }
    calculator := NewRewardCalculator(config)

    validatorStake := big.NewInt(1000)
    reward := calculator.CalculateBlockReward(validatorStake)
    expectedReward := big.NewInt(150) // Calculated manually for the test case

    assert.Equal(t, expectedReward.String(), reward.String(), "The reward calculation should match the expected outcome.")
}

// TestTransactionFeeDistribution ensures that the transaction fee distribution is correct.
func TestTransactionFeeDistribution(t *testing.T) {
    config := &RewardConfig{
        BaseReward:    big.NewInt(1000),
        TotalStake:    big.NewInt(10000),
        DynamicFactor: 1.5,
    }
    calculator := NewRewardCalculator(config)
    fees := []*big.Int{big.NewInt(100), big.NewInt(200), big.NewInt(300)}
    blockReward := big.NewInt(1000)
    totalReward := calculator.DistributeTransactionFees(fees, blockReward)

    assert.Equal(t, big.NewInt(600).String(), totalReward.String(), "The total transaction fee reward should be correctly distributed among the validators.")
}

// TestBlockValidation verifies that blocks are validated correctly integrating the PoH mechanism.
func TestBlockValidation(t *testing.T) {
    poh := NewPoH()
    block := &blockchain.Block{
        Transactions: []*blockchain.Transaction{
            blockchain.NewTransaction("tx1", "data1"),
            blockchain.NewTransaction("tx2", "data2"),
        },
        PrevHash: "previous_hash",
    }

    poh.ValidateBlock(block)
    assert.True(t, block.IsValid, "The block should be valid after passing the PoH validation.")
}

