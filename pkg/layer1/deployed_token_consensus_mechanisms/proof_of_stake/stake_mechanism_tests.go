package proof_of_stake

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStakeTokens(t *testing.T) {
	pm := NewStakingPool()
	stakeholderID := "stakeholder1"
	pm.Stakeholders[stakeholderID] = &Stakeholder{
		ID: stakeholderID,
		Balance: big.NewInt(1000),
		StakedAmount: big.NewInt(0),
	}

	// Test staking an acceptable amount
	err := pm.StakeTokens(stakeholderID, big.NewInt(500))
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(500), pm.Stakeholders[stakeholderID].StakedAmount)
	assert.Equal(t, big.NewInt(500), pm.Stakeholders[stakeholderID].Balance)

	// Test staking more than available balance
	err = pm.StakeTokens(stakeholderID, big.NewInt(600))
	require.Error(t, err)
	assert.Equal(t, "insufficient balance to stake the specified amount", err.Error())

	// Test staking with a negative amount
	err = pm.StakeTokens(stakeholderID, big.NewInt(-100))
	require.Error(t, err)
	assert.Equal(t, "invalid amount: staking amount must be positive", err.Error())
}

func TestUnstakeTokens(t *testing.T) {
	pm := NewStakingPool()
	stakeholderID := "stakeholder1"
	pm.Stakeholders[stakeholderID] = &Stakeholder{
		ID: stakeholderID,
		Balance: big.NewInt(500),
		StakedAmount: big.NewInt(500),
	}

	// Test unstaking an acceptable amount
	err := pm.UnstakeTokens(stakeholderID, big.NewInt(300))
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(200), pm.Stakeholders[stakeholderID].StakedAmount)
	assert.Equal(t, big.NewInt(800), pm.Stakeholders[stakeholderID].Balance)

	// Test unstaking more than staked amount
	err = pm.UnstakeTokens(stakeholderID, big.NewInt(500))
	require.Error(t, err)
	assert.Equal(t, "attempting to unstake more than the current staked amount", err.Error())

	// Test unstaking a negative amount
	err = pm.UnstakeTokens(stakeholderID, big.NewInt(-100))
	require.Error(t, err)
	assert.Equal(t, "invalid amount: unstaking amount must be positive", err.Error())
}

func TestCalculateRewards(t *testing.T) {
	pm := NewStakingPool()
	stakeholderID := "stakeholder1"
	pm.Stakeholders[stakeholderID] = &Stakeholder{
		ID: stakeholderID,
		Balance: big.NewInt(1000),
		StakedAmount: big.NewInt(500),
	}

	pm.CalculateRewards(0.05) // 5% reward rate
	expectedReward := new(big.Int).Mul(big.NewInt(500), big.NewInt(5)) // 5% of 500
	expectedBalance := new(big.Int).Add(big.NewInt(1000), expectedReward)
	assert.Equal(t, expectedBalance, pm.Stakeholders[stakeholderID].Balance)
}

// Additional tests for serialization and encryption functions can be added here to ensure robustness and security.

