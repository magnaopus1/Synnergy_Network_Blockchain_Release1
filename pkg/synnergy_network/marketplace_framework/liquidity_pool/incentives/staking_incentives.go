package incentives

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/ethereum/go-ethereum/common"
)

// StakingIncentiveProgram represents a staking incentive program
type StakingIncentiveProgram struct {
	ID                  common.Hash
	Name                string
	StartTime           time.Time
	EndTime             time.Time
	RewardToken         common.Address
	TotalRewardAmount   *big.Int
	DistributedRewards  *big.Int
	Lock                sync.Mutex
	Participants        map[common.Address]*Staker
	StakingRewardRate   *big.Int // reward per token staked per second
	MinimumStakeAmount  *big.Int
	MinimumStakePeriod  time.Duration
}

// Staker represents a participant in the staking incentive program
type Staker struct {
	Address           common.Address
	StakedAmount      *big.Int
	RewardDebt        *big.Int
	PendingRewards    *big.Int
	LastStakeTime     time.Time
	StakeEndTime      time.Time
	ClaimedRewards    *big.Int
}

// NewStakingIncentiveProgram initializes a new staking incentive program
func NewStakingIncentiveProgram(name string, startTime, endTime time.Time, rewardToken common.Address, totalRewardAmount, stakingRewardRate, minimumStakeAmount *big.Int, minimumStakePeriod time.Duration) *StakingIncentiveProgram {
	return &StakingIncentiveProgram{
		ID:                  generateProgramID(name, startTime, endTime, rewardToken),
		Name:                name,
		StartTime:           startTime,
		EndTime:             endTime,
		RewardToken:         rewardToken,
		TotalRewardAmount:   totalRewardAmount,
		DistributedRewards:  big.NewInt(0),
		StakingRewardRate:   stakingRewardRate,
		MinimumStakeAmount:  minimumStakeAmount,
		MinimumStakePeriod:  minimumStakePeriod,
		Participants:        make(map[common.Address]*Staker),
	}
}

// Stake allows a participant to stake a specified amount
func (p *StakingIncentiveProgram) Stake(address common.Address, amount *big.Int) error {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	if time.Now().Before(p.StartTime) || time.Now().After(p.EndTime) {
		return errors.New("staking program is not active")
	}

	if amount.Cmp(p.MinimumStakeAmount) < 0 {
		return errors.New("amount is less than minimum stake amount")
	}

	staker, exists := p.Participants[address]
	if !exists {
		staker = &Staker{
			Address:      address,
			StakedAmount: big.NewInt(0),
			RewardDebt:   big.NewInt(0),
			PendingRewards: big.NewInt(0),
			ClaimedRewards: big.NewInt(0),
		}
		p.Participants[address] = staker
	}

	staker.PendingRewards.Add(staker.PendingRewards, p.calculatePendingRewards(staker))
	staker.StakedAmount.Add(staker.StakedAmount, amount)
	staker.LastStakeTime = time.Now()
	staker.StakeEndTime = staker.LastStakeTime.Add(p.MinimumStakePeriod)
	staker.RewardDebt = p.calculateRewardDebt(staker)

	return nil
}

// Unstake allows a participant to unstake their tokens
func (p *StakingIncentiveProgram) Unstake(address common.Address) (*big.Int, error) {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	staker, exists := p.Participants[address]
	if !exists {
		return nil, errors.New("staker not found")
	}

	if time.Now().Before(staker.StakeEndTime) {
		return nil, errors.New("cannot unstake before minimum stake period")
	}

	staker.PendingRewards.Add(staker.PendingRewards, p.calculatePendingRewards(staker))
	stakedAmount := staker.StakedAmount
	staker.StakedAmount = big.NewInt(0)
	staker.RewardDebt = p.calculateRewardDebt(staker)

	return stakedAmount, nil
}

// ClaimRewards allows a participant to claim their pending rewards
func (p *StakingIncentiveProgram) ClaimRewards(address common.Address) (*big.Int, error) {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	staker, exists := p.Participants[address]
	if !exists {
		return nil, errors.New("staker not found")
	}

	staker.PendingRewards.Add(staker.PendingRewards, p.calculatePendingRewards(staker))
	rewards := staker.PendingRewards
	staker.PendingRewards = big.NewInt(0)
	staker.ClaimedRewards.Add(staker.ClaimedRewards, rewards)

	return rewards, nil
}

// calculatePendingRewards calculates the pending rewards for a staker
func (p *StakingIncentiveProgram) calculatePendingRewards(staker *Staker) *big.Int {
	duration := big.NewInt(time.Now().Sub(staker.LastStakeTime).Seconds())
	pendingRewards := new(big.Int).Mul(staker.StakedAmount, p.StakingRewardRate)
	pendingRewards.Mul(pendingRewards, duration)
	return pendingRewards
}

// calculateRewardDebt calculates the reward debt for a staker
func (p *StakingIncentiveProgram) calculateRewardDebt(staker *Staker) *big.Int {
	rewardDebt := new(big.Int).Mul(staker.StakedAmount, p.StakingRewardRate)
	return rewardDebt
}

// generateProgramID generates a unique ID for the staking incentive program
func generateProgramID(name string, startTime, endTime time.Time, rewardToken common.Address) common.Hash {
	data := fmt.Sprintf("%s:%v:%v:%s", name, startTime.Unix(), endTime.Unix(), rewardToken.Hex())
	hash := sha256.Sum256([]byte(data))
	return common.BytesToHash(hash[:])
}

// SecureKey generates a secure key using Argon2
func SecureKey(password, salt []byte, keyLen int) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, 16)
		_, err := rand.Read(salt)
		if err != nil {
			return nil, err
		}
	}

	key := argon2.IDKey(password, salt, 1, 64*1024, 4, uint32(keyLen))
	return key, nil
}

// Example of how you could use the SecureKey function
func exampleSecureKeyUsage() {
	password := []byte("examplepassword")
	salt := []byte("examplesalt")
	key, err := SecureKey(password, salt, 32)
	if err != nil {
		fmt.Println("Error generating key:", err)
		return
	}
	fmt.Println("Generated key:", key)
}
