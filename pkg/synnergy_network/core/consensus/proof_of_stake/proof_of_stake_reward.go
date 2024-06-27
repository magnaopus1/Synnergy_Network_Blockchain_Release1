package consensus

import (
	"crypto/sha256"
	"math/big"
	"sync"
	"time"
)

// RewardDistributor manages the distribution of rewards to validators based on their stake and transaction processing.
type RewardDistributor struct {
	totalStaked      *big.Int
	rewardPool       *big.Int
	transactionFees  *big.Int
	mutex            sync.Mutex
	validators       map[string]*Validator
	rewardAdjustment func(*big.Int, *big.Int) *big.Int
	blockchainState  *BlockchainState
}

// BlockchainState holds the global state of the blockchain required for calculations.
type BlockchainState struct {
	TotalTransactions int
}

// Validator represents the structure for blockchain validators, including necessary cryptographic components.
type Validator struct {
	PublicKey       string
	Stake           *big.Int
	Transactions    int
	EffectiveStake  *big.Int
	TransactionFees *big.Int
	Reward          *big.Int
	LastActive      time.Time
}

// NewRewardDistributor creates a new instance of RewardDistributor with initial values and setups.
func NewRewardDistributor(initialPool *big.Int, blockchainState *BlockchainState) *RewardDistributor {
	return &RewardDistributor{
		totalStaked:     big.NewInt(0),
		rewardPool:      initialPool,
		transactionFees: big.NewInt(0),
		validators:      make(map[string]*Validator),
		blockchainState: blockchainState,
	}
}

// UpdateRewards recalculates and distributes the rewards to each validator based on multiple factors.
func (rd *RewardDistributor) UpdateRewards() {
	rd.mutex.Lock()
	defer rd.mutex.Unlock()

	totalTransactions := big.NewInt(int64(rd.blockchainState.TotalTransactions))
	for _, v := range rd.validators {
		if time.Since(v.LastActive) > 24*time.Hour {
			continue // Skip inactive validators to prevent reward accrual
		}
		v.Reward = rd.calculateReward(v, totalTransactions)
	}
}

// calculateReward determines the reward for a single validator incorporating stake, transaction volume, and fees.
func (rd *RewardDistributor) calculateReward(v *Validator, totalTransactions *big.Int) *big.Int {
	stakeRatio := new(big.Int).Div(v.Stake, rd.totalStaked)
	transactionRatio := new(big.Int).Div(big.NewInt(int64(v.Transactions)), totalTransactions)

	// Calculate transaction fee rewards and base rewards from the reward pool
	feeComponent := new(big.Int).Mul(transactionRatio, rd.transactionFees)
	baseReward := new(big.Int).Mul(stakeRatio, rd.rewardPool)
	baseReward.Mul(baseReward, transactionRatio) // Base reward proportional to stake and transactions
	baseReward.Add(baseReward, feeComponent)     // Total reward includes a portion of the transaction fees

	return baseReward
}

// RegisterValidator adds a new validator to the pool and updates the staking total.
func (rd *RewardDistributor) RegisterValidator(validator *Validator) {
	rd.mutex.Lock()
	defer rd.mutex.Unlock()

	rd.validators[validator.PublicKey] = validator
	rd.totalStaked.Add(rd.totalStaked, validator.Stake)
}

// UpdateTransactionFees adjusts the total transaction fees pool, recalculating from recent block transactions.
func (rd *RewardDistributor) UpdateTransactionFees(fees *big.Int) {
	rd.mutex.Lock()
	defer rd.mutex.Unlock()

	rd.transactionFees.Add(rd.transactionFees, fees)
}

// TransactionHash generates a hash for transaction data, providing a cryptographic security layer for transaction verification.
func TransactionHash(txData []byte) []byte {
	hash := sha256.Sum256(txData)
	return hash[:]
}
