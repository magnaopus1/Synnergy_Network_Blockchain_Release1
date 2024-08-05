package liquidity_management

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/crypto/scrypt"
)

// LiquidityMiningProgram represents a liquidity mining program in the liquidity pool
type LiquidityMiningProgram struct {
	client        *ethclient.Client
	poolAddress   common.Address
	rewardsToken  common.Address
	duration      time.Duration
	totalRewards  *big.Int
	rewardRate    *big.Float
	stakedAmounts map[common.Address]*big.Int
	rewardPerTokenStored *big.Float
	userRewardPerTokenPaid map[common.Address]*big.Float
	rewards      map[common.Address]*big.Float
	mu           sync.Mutex
}

// NewLiquidityMiningProgram creates a new instance of LiquidityMiningProgram
func NewLiquidityMiningProgram(client *ethclient.Client, poolAddress, rewardsToken common.Address, duration time.Duration, totalRewards *big.Int) *LiquidityMiningProgram {
	lmp := &LiquidityMiningProgram{
		client:        client,
		poolAddress:   poolAddress,
		rewardsToken:  rewardsToken,
		duration:      duration,
		totalRewards:  totalRewards,
		rewardRate:    new(big.Float).Quo(new(big.Float).SetInt(totalRewards), new(big.Float).SetInt64(int64(duration.Seconds()))),
		stakedAmounts: make(map[common.Address]*big.Int),
		rewardPerTokenStored: new(big.Float),
		userRewardPerTokenPaid: make(map[common.Address]*big.Float),
		rewards:      make(map[common.Address]*big.Float),
	}
	go lmp.updateRewardRate()
	return lmp
}

// Stake allows a user to stake tokens in the liquidity mining program
func (lmp *LiquidityMiningProgram) Stake(user common.Address, amount *big.Int) error {
	lmp.mu.Lock()
	defer lmp.mu.Unlock()

	lmp.updateReward(user)
	if _, exists := lmp.stakedAmounts[user]; !exists {
		lmp.stakedAmounts[user] = big.NewInt(0)
	}
	lmp.stakedAmounts[user].Add(lmp.stakedAmounts[user], amount)

	// Update the user's reward per token paid to the current reward per token stored
	lmp.userRewardPerTokenPaid[user] = new(big.Float).Set(lmp.rewardPerTokenStored)

	// TODO: Implement the actual staking mechanism, such as transferring tokens to the contract
	return nil
}

// Withdraw allows a user to withdraw their staked tokens from the liquidity mining program
func (lmp *LiquidityMiningProgram) Withdraw(user common.Address, amount *big.Int) error {
	lmp.mu.Lock()
	defer lmp.mu.Unlock()

	if _, exists := lmp.stakedAmounts[user]; !exists || lmp.stakedAmounts[user].Cmp(amount) < 0 {
		return errors.New("insufficient staked amount")
	}

	lmp.updateReward(user)
	lmp.stakedAmounts[user].Sub(lmp.stakedAmounts[user], amount)

	// Update the user's reward per token paid to the current reward per token stored
	lmp.userRewardPerTokenPaid[user] = new(big.Float).Set(lmp.rewardPerTokenStored)

	// TODO: Implement the actual withdrawal mechanism, such as transferring tokens back to the user
	return nil
}

// ClaimReward allows a user to claim their accrued rewards
func (lmp *LiquidityMiningProgram) ClaimReward(user common.Address) (*big.Float, error) {
	lmp.mu.Lock()
	defer lmp.mu.Unlock()

	lmp.updateReward(user)
	reward, exists := lmp.rewards[user]
	if !exists || reward.Cmp(big.NewFloat(0)) == 0 {
		return nil, errors.New("no rewards to claim")
	}

	lmp.rewards[user] = big.NewFloat(0)
	// TODO: Implement the actual reward claiming mechanism, such as transferring rewards tokens to the user
	return reward, nil
}

// updateRewardRate periodically updates the reward rate based on the total staked amount
func (lmp *LiquidityMiningProgram) updateRewardRate() {
	ticker := time.NewTicker(time.Hour)
	for range ticker.C {
		lmp.mu.Lock()

		totalStaked := big.NewInt(0)
		for _, amount := range lmp.stakedAmounts {
			totalStaked.Add(totalStaked, amount)
		}

		if totalStaked.Cmp(big.NewInt(0)) > 0 {
			lmp.rewardRate = new(big.Float).Quo(new(big.Float).SetInt(lmp.totalRewards), new(big.Float).SetInt(totalStaked))
		} else {
			lmp.rewardRate = new(big.Float)
		}

		lmp.mu.Unlock()
	}
}

// updateReward updates the reward for a specific user
func (lmp *LiquidityMiningProgram) updateReward(user common.Address) {
	rewardPerToken := lmp.rewardPerToken()
	if _, exists := lmp.rewards[user]; !exists {
		lmp.rewards[user] = big.NewFloat(0)
	}

	if _, exists := lmp.userRewardPerTokenPaid[user]; !exists {
		lmp.userRewardPerTokenPaid[user] = new(big.Float)
	}

	userRewardPerTokenPaid := lmp.userRewardPerTokenPaid[user]
	stakedAmount, exists := lmp.stakedAmounts[user]
	if !exists {
		stakedAmount = big.NewInt(0)
	}

	userReward := new(big.Float).Sub(rewardPerToken, userRewardPerTokenPaid)
	userReward.Mul(userReward, new(big.Float).SetInt(stakedAmount))
	lmp.rewards[user].Add(lmp.rewards[user], userReward)

	lmp.rewardPerTokenStored = rewardPerToken
}

// rewardPerToken calculates the current reward per token
func (lmp *LiquidityMiningProgram) rewardPerToken() *big.Float {
	totalStaked := big.NewInt(0)
	for _, amount := range lmp.stakedAmounts {
		totalStaked.Add(totalStaked, amount)
	}

	if totalStaked.Cmp(big.NewInt(0)) == 0 {
		return lmp.rewardPerTokenStored
	}

	newRewardPerToken := new(big.Float).Set(lmp.rewardPerTokenStored)
	newRewardPerToken.Add(newRewardPerToken, new(big.Float).Quo(lmp.rewardRate, new(big.Float).SetInt(totalStaked)))
	return newRewardPerToken
}

// EncryptData encrypts data using AES
func EncryptData(key, data []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using AES
func DecryptData(key []byte, cipherHex string) ([]byte, error) {
	ciphertext, err := hex.DecodeString(cipherHex)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// GenerateEncryptionKey generates a secure encryption key using scrypt
func GenerateEncryptionKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 16384, 8, 1, 32)
}

// sendTransaction sends a transaction to the blockchain
func (lmp *LiquidityMiningProgram) sendTransaction(txData []byte) (*types.Transaction, error) {
	// TODO: Implement the method to send a transaction using lmp.client
	// This method should handle creating and sending a transaction with the provided data.
	return nil, errors.New("sendTransaction method not implemented")
}

// MonitorRewards continuously monitors the rewards in the liquidity mining program
func (lmp *LiquidityMiningProgram) MonitorRewards() {
	// TODO: Implement reward monitoring logic
	// This method should continuously monitor the rewards in the program and trigger alerts or actions based on predefined conditions.
}

// GetPoolAddress retrieves the address of the liquidity pool
func (lmp *LiquidityMiningProgram) GetPoolAddress() common.Address {
	lmp.mu.Lock()
	defer lmp.mu.Unlock()
	return lmp.poolAddress
}
