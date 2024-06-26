package proof_of_stake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"time"

	"github.com/pkg/errors"
)

// Stakeholder defines an individual with the ability to stake tokens.
type Stakeholder struct {
	ID           string
	Balance      *big.Int
	StakedAmount *big.Int
}

// StakingPool represents the collective staked tokens and their associated data.
type StakingPool struct {
	TotalStaked *big.Int
	Stakeholders map[string]*Stakeholder
}

// NewStakingPool initializes a new staking pool with empty stakeholders and total stake.
func NewStakingPool() *StakingPool {
	return &StakingPool{
		TotalStaked: big.NewInt(0),
		Stakeholders: make(map[string]*Stakeholder),
	}
}

// StakeTokens allows a stakeholder to stake a specified amount of tokens.
func (sp *StakingPool) StakeTokens(stakeholderID string, amount *big.Int) error {
	if amount.Sign() <= 0 {
		return errors.New("invalid amount: staking amount must be positive")
	}

	stakeholder, exists := sp.Stakeholders[stakeholderID]
	if !exists {
		stakeholder = &Stakeholder{
			ID: stakeholderID,
			Balance: big.NewInt(0),
			StakedAmount: big.NewInt(0),
		}
		sp.Stakeholders[stakeholderID] = stakeholder
	}

	if stakeholder.Balance.Cmp(amount) < 0 {
		return errors.New("insufficient balance to stake the specified amount")
	}

	stakeholder.Balance.Sub(stakeholder.Balance, amount)
	stakeholder.StakedAmount.Add(stakeholder.StakedAmount, amount)
	sp.TotalStaked.Add(sp.TotalStaked, amount)

	return nil
}

// CalculateRewards computes the rewards for all stakeholders based on their staked tokens.
func (sp *StakingPool) CalculateRewards(rewardRate float64) {
	for _, stakeholder := range sp.Stakeholders {
		reward := new(big.Float).Mul(new(big.Float).SetInt(stakeholder.StakedAmount), big.NewFloat(rewardRate))
		rewardInt, _ := reward.Int(nil)
		stakeholder.Balance.Add(stakeholder.Balance, rewardInt)
	}
}

// UnstakeTokens allows a stakeholder to remove some or all of their staked tokens.
func (sp *StakingPool) UnstakeTokens(stakeholderID string, amount *big.Int) error {
	if amount.Sign() <= 0 {
		return errors.New("invalid amount: unstaking amount must be positive")
	}

	stakeholder, exists := sp.Stakeholders[stakeholderID]
	if !exists {
		return errors.New("stakeholder not found")
	}

	if stakeholder.StakedAmount.Cmp(amount) < 0 {
		return errors.New("attempting to unstake more than the current staked amount")
	}

	stakeholder.StakedAmount.Sub(stakeholder.StakedAmount, amount)
	stakeholder.Balance.Add(stakeholder.Balance, amount)
	sp.TotalStaked.Sub(sp.TotalStaked, amount)

	return nil
}

// SerializeStakingPool encrypts and serializes the staking pool for secure storage.
func (sp *StakingPool) SerializeStakingPool(encryptionKey []byte) ([]byte, error) {
	data, err := json.Marshal(sp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal staking pool")
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher block")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce")
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

// DeserializeStakingPool decrypts and deserializes the staking pool.
func DeserializeStakingPool(data, encryptionKey []byte) (*StakingPool, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher block")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("invalid data size: too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt data")
	}

	var sp StakingPool
	if err := json.Unmarshal(decrypted, &sp); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal staking pool")
	}

	return &sp, nil
}

// Ensure this file provides comprehensive handling of stake mechanisms with rigorous error checking and robust encryption features.
