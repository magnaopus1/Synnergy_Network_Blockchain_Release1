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

// ReferralProgram represents a referral program
type ReferralProgram struct {
	ID                   common.Hash
	Name                 string
	StartTime            time.Time
	EndTime              time.Time
	RewardToken          common.Address
	TotalRewardAmount    *big.Int
	DistributedRewards   *big.Int
	Lock                 sync.Mutex
	Referrers            map[common.Address]*Referrer
	ReferralRewardAmount *big.Int
}

// Referrer represents a referrer in the referral program
type Referrer struct {
	Address            common.Address
	ReferralCount      int
	PendingRewards     *big.Int
	ClaimedRewards     *big.Int
	ReferredAddresses  map[common.Address]bool
}

// NewReferralProgram initializes a new referral program
func NewReferralProgram(name string, startTime, endTime time.Time, rewardToken common.Address, totalRewardAmount, referralRewardAmount *big.Int) *ReferralProgram {
	return &ReferralProgram{
		ID:                   generateProgramID(name, startTime, endTime, rewardToken),
		Name:                 name,
		StartTime:            startTime,
		EndTime:              endTime,
		RewardToken:          rewardToken,
		TotalRewardAmount:    totalRewardAmount,
		DistributedRewards:   big.NewInt(0),
		ReferralRewardAmount: referralRewardAmount,
		Referrers:            make(map[common.Address]*Referrer),
	}
}

// AddReferrer adds a referrer to the referral program
func (p *ReferralProgram) AddReferrer(referrer *Referrer) error {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	if time.Now().Before(p.StartTime) || time.Now().After(p.EndTime) {
		return errors.New("referral program is not active")
	}

	if _, exists := p.Referrers[referrer.Address]; exists {
		return errors.New("referrer already exists")
	}

	referrer.PendingRewards = big.NewInt(0)
	referrer.ClaimedRewards = big.NewInt(0)
	referrer.ReferredAddresses = make(map[common.Address]bool)
	p.Referrers[referrer.Address] = referrer

	return nil
}

// AddReferral adds a referral to a referrer
func (p *ReferralProgram) AddReferral(referrerAddress, referredAddress common.Address) error {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	referrer, exists := p.Referrers[referrerAddress]
	if !exists {
		return errors.New("referrer not found")
	}

	if time.Now().Before(p.StartTime) || time.Now().After(p.EndTime) {
		return errors.New("referral program is not active")
	}

	if referrer.ReferredAddresses[referredAddress] {
		return errors.New("address already referred by this referrer")
	}

	referrer.ReferredAddresses[referredAddress] = true
	referrer.ReferralCount++
	referrer.PendingRewards.Add(referrer.PendingRewards, p.ReferralRewardAmount)
	p.DistributedRewards.Add(p.DistributedRewards, p.ReferralRewardAmount)

	return nil
}

// ClaimRewards allows a referrer to claim their pending rewards
func (p *ReferralProgram) ClaimRewards(address common.Address) (*big.Int, error) {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	referrer, exists := p.Referrers[address]
	if !exists {
		return nil, errors.New("referrer not found")
	}

	if time.Now().Before(p.StartTime) || time.Now().After(p.EndTime) {
		return nil, errors.New("referral program is not active")
	}

	rewards := referrer.PendingRewards
	referrer.PendingRewards = big.NewInt(0)
	referrer.ClaimedRewards.Add(referrer.ClaimedRewards, rewards)
	return rewards, nil
}

// generateProgramID generates a unique ID for the referral program
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
