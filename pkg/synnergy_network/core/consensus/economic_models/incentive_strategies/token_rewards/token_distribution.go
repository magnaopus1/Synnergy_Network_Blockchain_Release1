package token_rewards

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/core/crypto"
)

// RewardType defines the type of reward
type RewardType string

const (
	MiningReward    RewardType = "mining"
	StakingReward   RewardType = "staking"
	GovernanceReward RewardType = "governance"
)

// Reward defines the structure of a token reward
type Reward struct {
	Type       RewardType
	Amount     *big.Int
	Recipient  string
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

// TokenDistributionManager manages the distribution of token rewards
type TokenDistributionManager struct {
	rewards map[string][]*Reward
	mu      sync.Mutex
}

// NewTokenDistributionManager initializes a new TokenDistributionManager
func NewTokenDistributionManager() *TokenDistributionManager {
	return &TokenDistributionManager{
		rewards: make(map[string][]*Reward),
	}
}

// IssueReward issues a new token reward to a user
func (tdm *TokenDistributionManager) IssueReward(recipient string, rewardType RewardType, amount *big.Int, duration time.Duration) (*Reward, error) {
	if amount.Cmp(big.NewInt(0)) <= 0 {
		return nil, errors.New("reward amount must be positive")
	}

	reward := &Reward{
		Type:      rewardType,
		Amount:    amount,
		Recipient: recipient,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(duration),
	}

	tdm.mu.Lock()
	defer tdm.mu.Unlock()
	tdm.rewards[recipient] = append(tdm.rewards[recipient], reward)

	fmt.Printf("Issued %s reward to user %s with amount %s\n", rewardType, recipient, amount.String())
	return reward, nil
}

// RedeemReward redeems a token reward for a user
func (tdm *TokenDistributionManager) RedeemReward(recipient string, rewardType RewardType) (*Reward, error) {
	tdm.mu.Lock()
	defer tdm.mu.Unlock()

	userRewards, exists := tdm.rewards[recipient]
	if !exists || len(userRewards) == 0 {
		return nil, fmt.Errorf("no rewards found for user %s", recipient)
	}

	var redeemedReward *Reward
	for i, reward := range userRewards {
		if reward.Type == rewardType && time.Now().Before(reward.ExpiresAt) {
			redeemedReward = reward
			// Remove redeemed reward
			tdm.rewards[recipient] = append(userRewards[:i], userRewards[i+1:]...)
			break
		}
	}

	if redeemedReward == nil {
		return nil, fmt.Errorf("no valid reward of type %s found for user %s", rewardType, recipient)
	}

	fmt.Printf("Redeemed %s reward for user %s with amount %s\n", rewardType, recipient, redeemedReward.Amount.String())
	return redeemedReward, nil
}

// GetRewards lists all rewards for a user
func (tdm *TokenDistributionManager) GetRewards(recipient string) ([]*Reward, error) {
	tdm.mu.Lock()
	defer tdm.mu.Unlock()

	userRewards, exists := tdm.rewards[recipient]
	if !exists {
		return nil, fmt.Errorf("no rewards found for user %s", recipient)
	}

	return userRewards, nil
}

// CleanExpiredRewards removes expired rewards from the system
func (tdm *TokenDistributionManager) CleanExpiredRewards() {
	tdm.mu.Lock()
	defer tdm.mu.Unlock()

	for recipient, rewards := range tdm.rewards {
		var validRewards []*Reward
		for _, reward := range rewards {
			if time.Now().Before(reward.ExpiresAt) {
				validRewards = append(validRewards, reward)
			} else {
				fmt.Printf("Removed expired reward of type %s for user %s with amount %s\n", reward.Type, recipient, reward.Amount.String())
			}
		}
		tdm.rewards[recipient] = validRewards
	}
}

// EncryptReward encrypts a reward using AES encryption
func (tdm *TokenDistributionManager) EncryptReward(reward *Reward, passphrase string) ([]byte, error) {
	rewardBytes, err := reward.MarshalBinary()
	if err != nil {
		return nil, err
	}
	encryptedReward, err := crypto.EncryptAES(rewardBytes, passphrase)
	if err != nil {
		return nil, err
	}
	return encryptedReward, nil
}

// DecryptReward decrypts a reward using AES encryption
func (tdm *TokenDistributionManager) DecryptReward(encryptedReward []byte, passphrase string) (*Reward, error) {
	decryptedBytes, err := crypto.DecryptAES(encryptedReward, passphrase)
	if err != nil {
		return nil, err
	}
	var reward Reward
	err = reward.UnmarshalBinary(decryptedBytes)
	if err != nil {
		return nil, err
	}
	return &reward, nil
}

// MarshalBinary serializes a Reward into a binary format
func (r *Reward) MarshalBinary() ([]byte, error) {
	type alias Reward
	return json.Marshal((*alias)(r))
}

// UnmarshalBinary deserializes a Reward from a binary format
func (r *Reward) UnmarshalBinary(data []byte) error {
	type alias Reward
	return json.Unmarshal(data, (*alias)(r))
}

func main() {
	tdm := NewTokenDistributionManager()
	amount := big.NewInt(1000)

	// Issue a reward
	reward, err := tdm.IssueReward("user1", MiningReward, amount, 7*24*time.Hour) // 7 days expiry
	if err != nil {
		fmt.Println("Error issuing reward:", err)
		return
	}

	fmt.Println("Issued reward:", reward)

	// Encrypt the reward
	passphrase := "securepassphrase"
	encryptedReward, err := tdm.EncryptReward(reward, passphrase)
	if err != nil {
		fmt.Println("Error encrypting reward:", err)
		return
	}

	fmt.Println("Encrypted reward:", encryptedReward)

	// Decrypt the reward
	decryptedReward, err := tdm.DecryptReward(encryptedReward, passphrase)
	if err != nil {
		fmt.Println("Error decrypting reward:", err)
		return
	}

	fmt.Println("Decrypted reward:", decryptedReward)

	// Redeem a reward
	redeemedReward, err := tdm.RedeemReward("user1", MiningReward)
	if err != nil {
		fmt.Println("Error redeeming reward:", err)
		return
	}

	fmt.Println("Redeemed reward:", redeemedReward)

	// List rewards for a user
	rewards, err := tdm.GetRewards("user1")
	if err != nil {
		fmt.Println("Error listing rewards:", err)
		return
	}

	fmt.Println("Rewards for user1:", rewards)

	// Clean expired rewards
	tdm.CleanExpiredRewards()
}
