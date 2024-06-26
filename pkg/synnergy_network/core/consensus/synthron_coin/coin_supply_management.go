package synthron_coin

import (
	"errors"
	"math"
	"sync"
)

// CoinSupplyManager manages the parameters and state of the coin supply.
type CoinSupplyManager struct {
	sync.Mutex
	totalSupply           float64
	maxSupply             float64
	initialSupply         float64
	blockHeight           uint64
	rewardPerBlock        float64
	halvingInterval       uint64
	communityFund         float64
	communityFundReserved float64
	stakingRewardsPool    float64
}

// NewCoinSupplyManager creates a new coin supply manager with initial settings.
func NewCoinSupplyManager(initialSupply, maxSupply float64, halvingInterval uint64) *CoinSupplyManager {
	return &CoinSupplyManager{
		totalSupply:    initialSupply,
		initialSupply:  initialSupply,
		maxSupply:      maxSupply,
		halvingInterval: halvingInterval,
		rewardPerBlock: initialSupply / 10, // Initial reward setting, subject to change.
	}
}

// CurrentSupply returns the current total supply.
func (m *CoinSupplyManager) CurrentSupply() float64 {
	m.Lock()
	defer m.Unlock()
	return m.totalSupply
}

// IncrementBlockHeight progresses the blockchain height and adjusts reward distribution.
func (m *CoinSupplyManager) IncrementBlockHeight() error {
	m.Lock()
	defer m.Unlock()

	m.blockHeight++
	if m.blockHeight%m.halvingInterval == 0 {
		m.halveRewards()
	}

	if m.totalSupply >= m.maxSupply {
		return errors.New("maximum supply reached, no more coins can be mined")
	}

	m.issueBlockReward()
	return nil
}

// halveRewards halves the block reward.
func (m *CoinSupplyManager) halveRewards() {
	m.rewardPerBlock /= 2
}

// issueBlockReward issues new coins as block rewards, ensuring not to exceed max supply.
func (m *CoinSupplyManager) issueBlockReward() {
	if m.totalSupply+m.rewardPerBlock > m.maxSupply {
		m.rewardPerBlock = m.maxSupply - m.totalSupply
	}
	m.totalSupply += m.rewardPerBlock
	m.allocateRewards()
}

// allocateRewards allocates block rewards to the community fund and staking rewards.
func (m *CoinSupplyManager) allocateRewards() {
	communityAllocation := m.rewardPerBlock * 0.1  // 10% to community fund
	stakingAllocation := m.rewardPerBlock * 0.25 // 25% to staking rewards

	m.communityFund += communityAllocation
	m.stakingRewardsPool += stakingAllocation
}

// DistributeCommunityFund allocates funds for community projects.
func (m *CoinSupplyManager) DistributeCommunityFund(amount float64) error {
	m.Lock()
	defer m.Unlock()

	if amount > m.communityFund {
		return errors.New("insufficient funds in community pool")
	}

	m.communityFund -= amount
	m.communityFundReserved += amount
	return nil
}

// RewardStakingParticipants distributes rewards to stakers.
func (m *CoinSupplyManager) RewardStakingParticipants(stakers map[string]float64) {
	m.Lock()
	defer m.Unlock()

	totalStakes := 0.0
	for _, stake := range stakers {
		totalStakes += stake
	}

	for address, stake := range stakers {
		reward := (stake / totalStakes) * m.stakingRewardsPool
		// In a real implementation, this would update the staker's balance.
		fmt.Printf("Reward to %s: %.2f Synthron Coins\n", address, reward)
	}

	m.stakingRewardsPool = 0 // Reset after distribution
}

func main() {
	// Example usage
	manager := NewCoinSupplyManager(5000000, 500000000, 200000)
	for i := 0; i < 500000; i++ {
		if err := manager.IncrementBlockHeight(); err != nil {
			fmt.Println(err)
			break
		}
	}

	stakers := map[string]float64{
		"wallet1": 1500,
		"wallet2": 3500,
	}

	manager.RewardStakingParticipants(stakers)
	fmt.Printf("Total Supply after mining: %.2f\n", manager.CurrentSupply())
}
