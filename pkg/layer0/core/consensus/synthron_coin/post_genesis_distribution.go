package synthron_coin

import (
	"fmt"
	"log"
)

// Validator represents a node that validates transactions and maintains the blockchain.
type Validator struct {
	Address string
	Stake   float64
}

// CommunityProject represents initiatives and development projects funded by the blockchain.
type CommunityProject struct {
	ProjectID   string
	Funding     float64
	Description string
}

// DistributionManager manages the distribution of coins post-genesis.
type DistributionManager struct {
	Validators        []Validator
	CommunityProjects []CommunityProject
	StakingPool       float64
	TotalRewards      float64
}

// NewDistributionManager creates a new manager for handling post-genesis distributions.
func NewDistributionManager() *DistributionManager {
	return &DistributionManager{}
}

// AllocateRewards distributes block rewards to validators based on their stake.
func (dm *DistributionManager) AllocateRewards(blockReward float64) {
	totalStake := 0.0
	for _, v := range dm.Validators {
		totalStake += v.Stake
	}

	if totalStake == 0 {
		log.Println("No stakes found. Rewards distribution skipped.")
		return
	}

	for i, v := range dm.Validators {
		validatorReward := (v.Stake / totalStake) * blockReward
		dm.Validators[i].Stake += validatorReward // reinvesting the reward
		dm.TotalRewards += validatorReward
		fmt.Printf("Validator %s rewarded with %f Synthron Coins.\n", v.Address, validatorReward)
	}
}

// FundCommunityProject allocates funds to community-driven projects.
func (dm *DistributionManager) FundCommunityProject(projectID string, amount float64) error {
	for i, p := range dm.CommunityProjects {
		if p.ProjectID == projectID {
			dm.CommunityProjects[i].Funding += amount
			fmt.Printf("Project %s funded with %f Synthron Coins.\n", projectID, amount)
			return nil
		}
	}
	return fmt.Errorf("project ID %s not found", projectID)
}

// SetupStakingPool initializes the staking pool with a specified amount of coins.
func (dm *DistributionManager) SetupStakingPool(amount float64) {
	dm.StakingPool = amount
	fmt.Printf("Staking pool initialized with %f Synthron Coins.\n", amount)
}

func main() {
	// Initialization of the Distribution Manager
	dm := NewDistributionManager()

	// Example validators setup
	dm.Validators = []Validator{
		{"Validator1", 10000},
		{"Validator2", 15000},
	}

	// Example community projects setup
	dm.CommunityProjects = []CommunityProject{
		{"Proj1", 0, "Blockchain Education Initiative"},
		{"Proj2", 0, "Synthron Network Expansion"},
	}

	// Simulate block reward distribution
	dm.AllocateRewards(5000) // Total block reward

	// Fund a community project
	err := dm.FundCommunityProject("Proj1", 2000)
	if err != nil {
		log.Println("Funding error:", err)
	}

	// Setup staking pool
	dm.SetupStakingPool(100000)
}
