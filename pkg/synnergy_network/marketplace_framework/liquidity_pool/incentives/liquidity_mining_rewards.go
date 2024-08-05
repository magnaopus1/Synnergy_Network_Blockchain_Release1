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

// LiquidityMiningProgram represents a liquidity mining program
type LiquidityMiningProgram struct {
	ID                 common.Hash
	Name               string
	StartTime          time.Time
	EndTime            time.Time
	RewardToken        common.Address
	TotalRewardAmount  *big.Int
	DistributedRewards *big.Int
	Lock               sync.Mutex
	Participants       map[common.Address]*Participant
}

// Participant represents a participant in the liquidity mining program
type Participant struct {
	Address        common.Address
	StakedAmount   *big.Int
	RewardDebt     *big.Int
	PendingRewards *big.Int
}

// NewLiquidityMiningProgram initializes a new liquidity mining program
func NewLiquidityMiningProgram(name string, startTime, endTime time.Time, rewardToken common.Address, totalRewardAmount *big.Int) *LiquidityMiningProgram {
	return &LiquidityMiningProgram{
		ID:                 generateProgramID(name, startTime, endTime, rewardToken),
		Name:               name,
		StartTime:          startTime,
		EndTime:            endTime,
		RewardToken:        rewardToken,
		TotalRewardAmount:  totalRewardAmount,
		DistributedRewards: big.NewInt(0),
		Participants:       make(map[common.Address]*Participant),
	}
}

// AddParticipant adds a participant to the liquidity mining program
func (p *LiquidityMiningProgram) AddParticipant(participant *Participant) error {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	if time.Now().Before(p.StartTime) || time.Now().After(p.EndTime) {
		return errors.New("liquidity mining program is not active")
	}

	if _, exists := p.Participants[participant.Address]; exists {
		return errors.New("participant already exists")
	}

	participant.RewardDebt = big.NewInt(0)
	participant.PendingRewards = big.NewInt(0)
	p.Participants[participant.Address] = participant

	return nil
}

// UpdateParticipant updates the staked amount for a participant
func (p *LiquidityMiningProgram) UpdateParticipant(address common.Address, stakedAmount *big.Int) error {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	participant, exists := p.Participants[address]
	if !exists {
		return errors.New("participant not found")
	}

	if time.Now().Before(p.StartTime) || time.Now().After(p.EndTime) {
		return errors.New("liquidity mining program is not active")
	}

	participant.PendingRewards = calculatePendingRewards(participant, p)
	participant.StakedAmount = stakedAmount

	return nil
}

// DistributeRewards distributes rewards to participants based on their staked amount
func (p *LiquidityMiningProgram) DistributeRewards() error {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	if time.Now().Before(p.StartTime) || time.Now().After(p.EndTime) {
		return errors.New("liquidity mining program is not active")
	}

	totalStaked := big.NewInt(0)
	for _, participant := range p.Participants {
		totalStaked.Add(totalStaked, participant.StakedAmount)
	}

	if totalStaked.Cmp(big.NewInt(0)) == 0 {
		return errors.New("no staked amount found")
	}

	for _, participant := range p.Participants {
		reward := new(big.Int).Mul(participant.StakedAmount, p.TotalRewardAmount)
		reward.Div(reward, totalStaked)
		participant.PendingRewards.Add(participant.PendingRewards, reward)
		participant.RewardDebt.Add(participant.RewardDebt, reward)
		p.DistributedRewards.Add(p.DistributedRewards, reward)
	}

	return nil
}

// ClaimRewards allows a participant to claim their pending rewards
func (p *LiquidityMiningProgram) ClaimRewards(address common.Address) (*big.Int, error) {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	participant, exists := p.Participants[address]
	if !exists {
		return nil, errors.New("participant not found")
	}

	if time.Now().Before(p.StartTime) || time.Now().After(p.EndTime) {
		return nil, errors.New("liquidity mining program is not active")
	}

	rewards := participant.PendingRewards
	participant.PendingRewards = big.NewInt(0)
	return rewards, nil
}

// generateProgramID generates a unique ID for the liquidity mining program
func generateProgramID(name string, startTime, endTime time.Time, rewardToken common.Address) common.Hash {
	data := fmt.Sprintf("%s:%v:%v:%s", name, startTime.Unix(), endTime.Unix(), rewardToken.Hex())
	hash := sha256.Sum256([]byte(data))
	return common.BytesToHash(hash[:])
}

// calculatePendingRewards calculates the pending rewards for a participant
func calculatePendingRewards(participant *Participant, program *LiquidityMiningProgram) *big.Int {
	pending := new(big.Int).Sub(participant.StakedAmount, participant.RewardDebt)
	pending.Mul(pending, program.TotalRewardAmount)
	totalStaked := big.NewInt(0)
	for _, p := range program.Participants {
		totalStaked.Add(totalStaked, p.StakedAmount)
	}
	pending.Div(pending, totalStaked)
	return pending
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
