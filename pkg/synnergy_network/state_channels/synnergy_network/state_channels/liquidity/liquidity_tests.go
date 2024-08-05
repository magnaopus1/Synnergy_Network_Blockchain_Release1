package liquidity

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewDynamicLiquidityManagement(t *testing.T) {
	initialLiquidity := map[string]int64{
		"participantA": 100,
		"participantB": 200,
	}
	dlm := NewDynamicLiquidityManagement("pool1", []string{"participantA", "participantB"}, initialLiquidity)

	assert.Equal(t, "pool1", dlm.PoolID)
	assert.Equal(t, []string{"participantA", "participantB"}, dlm.ParticipantIDs)
	assert.Equal(t, initialLiquidity, dlm.LiquidityAmount)
	assert.Equal(t, LiquidityActive, dlm.Status)
}

func TestAddLiquidity(t *testing.T) {
	initialLiquidity := map[string]int64{
		"participantA": 100,
		"participantB": 200,
	}
	dlm := NewDynamicLiquidityManagement("pool1", []string{"participantA", "participantB"}, initialLiquidity)

	err := dlm.AddLiquidity("participantA", 50)
	assert.Nil(t, err)
	assert.Equal(t, int64(150), dlm.LiquidityAmount["participantA"])
}

func TestRemoveLiquidity(t *testing.T) {
	initialLiquidity := map[string]int64{
		"participantA": 100,
		"participantB": 200,
	}
	dlm := NewDynamicLiquidityManagement("pool1", []string{"participantA", "participantB"}, initialLiquidity)

	err := dlm.RemoveLiquidity("participantA", 50)
	assert.Nil(t, err)
	assert.Equal(t, int64(50), dlm.LiquidityAmount["participantA"])
}

func TestClosePool(t *testing.T) {
	initialLiquidity := map[string]int64{
		"participantA": 100,
		"participantB": 200,
	}
	dlm := NewDynamicLiquidityManagement("pool1", []string{"participantA", "participantB"}, initialLiquidity)

	err := dlm.ClosePool()
	assert.Nil(t, err)
	assert.Equal(t, LiquidityClosed, dlm.Status)
}

func TestEncryptDecryptLiquidity(t *testing.T) {
	initialLiquidity := map[string]int64{
		"participantA": 100,
		"participantB": 200,
	}
	dlm := NewDynamicLiquidityManagement("pool1", []string{"participantA", "participantB"}, initialLiquidity)
	key := []byte("encryptionkey123")

	encrypted, err := dlm.EncryptLiquidity(key)
	assert.Nil(t, err)

	newDLM := &DynamicLiquidityManagement{}
	err = newDLM.DecryptLiquidity(encrypted, key)
	assert.Nil(t, err)
	assert.Equal(t, dlm.PoolID, newDLM.PoolID)
	assert.Equal(t, dlm.ParticipantIDs, newDLM.ParticipantIDs)
	assert.Equal(t, dlm.LiquidityAmount, newDLM.LiquidityAmount)
	assert.Equal(t, dlm.Status, newDLM.Status)
}

func TestNewIncentiveMechanism(t *testing.T) {
	im := NewIncentiveMechanism("incentive1", "pool1", "participantA", 100)

	assert.Equal(t, "incentive1", im.IncentiveID)
	assert.Equal(t, "pool1", im.PoolID)
	assert.Equal(t, "participantA", im.ParticipantID)
	assert.Equal(t, int64(100), im.IncentiveAmount)
	assert.Equal(t, IncentiveActive, im.Status)
}

func TestClaimIncentive(t *testing.T) {
	im := NewIncentiveMechanism("incentive1", "pool1", "participantA", 100)

	err := im.ClaimIncentive()
	assert.Nil(t, err)
	assert.Equal(t, IncentiveClaimed, im.Status)
}

func TestEncryptDecryptIncentive(t *testing.T) {
	im := NewIncentiveMechanism("incentive1", "pool1", "participantA", 100)
	key := []byte("encryptionkey123")

	encrypted, err := im.EncryptIncentive(key)
	assert.Nil(t, err)

	newIM := &IncentiveMechanism{}
	err = newIM.DecryptIncentive(encrypted, key)
	assert.Nil(t, err)
	assert.Equal(t, im.IncentiveID, newIM.IncentiveID)
	assert.Equal(t, im.PoolID, newIM.PoolID)
	assert.Equal(t, im.ParticipantID, newIM.ParticipantID)
	assert.Equal(t, im.IncentiveAmount, newIM.IncentiveAmount)
	assert.Equal(t, im.Status, newIM.Status)
}

func TestNewLiquidityPool(t *testing.T) {
	initialLiquidity := map[string]int64{
		"participantA": 100,
		"participantB": 200,
	}
	lp := NewLiquidityPool("pool1", []string{"participantA", "participantB"}, initialLiquidity)

	assert.Equal(t, "pool1", lp.PoolID)
	assert.Equal(t, []string{"participantA", "participantB"}, lp.ParticipantIDs)
	assert.Equal(t, initialLiquidity, lp.LiquidityAmount)
	assert.Equal(t, PoolActive, lp.Status)
}

func TestAddLiquidityToPool(t *testing.T) {
	initialLiquidity := map[string]int64{
		"participantA": 100,
		"participantB": 200,
	}
	lp := NewLiquidityPool("pool1", []string{"participantA", "participantB"}, initialLiquidity)

	err := lp.AddLiquidity("participantA", 50)
	assert.Nil(t, err)
	assert.Equal(t, int64(150), lp.LiquidityAmount["participantA"])
}

func TestRemoveLiquidityFromPool(t *testing.T) {
	initialLiquidity := map[string]int64{
		"participantA": 100,
		"participantB": 200,
	}
	lp := NewLiquidityPool("pool1", []string{"participantA", "participantB"}, initialLiquidity)

	err := lp.RemoveLiquidity("participantA", 50)
	assert.Nil(t, err)
	assert.Equal(t, int64(50), lp.LiquidityAmount["participantA"])
}

func TestCloseLiquidityPool(t *testing.T) {
	initialLiquidity := map[string]int64{
		"participantA": 100,
		"participantB": 200,
	}
	lp := NewLiquidityPool("pool1", []string{"participantA", "participantB"}, initialLiquidity)

	err := lp.ClosePool()
	assert.Nil(t, err)
	assert.Equal(t, PoolClosed, lp.Status)
}

func TestEncryptDecryptLiquidityPool(t *testing.T) {
	initialLiquidity := map[string]int64{
		"participantA": 100,
		"participantB": 200,
	}
	lp := NewLiquidityPool("pool1", []string{"participantA", "participantB"}, initialLiquidity)
	key := []byte("encryptionkey123")

	encrypted, err := lp.EncryptPool(key)
	assert.Nil(t, err)

	newLP := &LiquidityPool{}
	err = newLP.DecryptPool(encrypted, key)
	assert.Nil(t, err)
	assert.Equal(t, lp.PoolID, newLP.PoolID)
	assert.Equal(t, lp.ParticipantIDs, newLP.ParticipantIDs)
	assert.Equal(t, lp.LiquidityAmount, newLP.LiquidityAmount)
	assert.Equal(t, lp.Status, newLP.Status)
}
