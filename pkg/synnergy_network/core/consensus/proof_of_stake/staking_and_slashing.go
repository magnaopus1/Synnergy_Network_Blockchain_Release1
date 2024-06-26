package proof_of_stake

import (
    "math/big"
    "time"
)

type Validator struct {
    Address        string
    Stake          *big.Int
    StartDate      time.Time
    IsSlashed      bool
    SlashedAmount  *big.Int
    LockupPeriod   time.Duration
}

type Blockchain struct {
    Validators []*Validator
    TotalStaked *big.Int
}

// NewValidator initializes a new validator struct
func NewValidator(address string, stakeAmount *big.Int, lockupPeriod time.Duration) *Validator {
    return &Validator{
        Address:      address,
        Stake:        stakeAmount,
        StartDate:    time.Now(),
        LockupPeriod: lockupPeriod,
    }
}

// AddValidator adds a new validator to the blockchain
func (bc *Blockchain) AddValidator(validator *Validator) {
    bc.Validators = append(bc.Validators, validator)
    bc.TotalStaked.Add(bc.TotalStaked, validator.Stake)
}

// CalculateSlashingAmount calculates the amount to be slashed based on severity
func (v *Validator) CalculateSlashingAmount(severity int) *big.Int {
    penaltyPercentage := big.NewInt(int64(severity * 10)) // 10% per severity level
    slashAmount := new(big.Int).Mul(v.Stake, penaltyPercentage)
    slashAmount.Div(slashAmount, big.NewInt(100))
    return slashAmount
}

// SlashValidator applies the slashing penalty to the validator
func (v *Validator) SlashValidator(severity int) {
    if v.IsSlashed {
        return
    }
    slashAmount := v.CalculateSlashingAmount(severity)
    v.Stake.Sub(v.Stake, slashAmount)
    v.SlashedAmount = slashAmount
    v.IsSlashed = true
}

// CheckLockupPeriod checks if the lockup period has passed for unstaking
func (v *Validator) CheckLockupPeriod() bool {
    return time.Since(v.StartDate) >= v.LockupPeriod
}

// RewardValidators distributes rewards to all active validators proportionally to their stakes
func (bc *Blockchain) RewardValidators(transactionVolume *big.Int) {
    totalTransactions := big.NewInt(1) // Placeholder for the total number of transactions
    for _, v := range bc.Validators {
        if !v.IsSlashed {
            reward := new(big.Int).Mul(v.Stake, transactionVolume)
            reward.Div(reward, totalTransactions)
            reward.Div(reward, bc.TotalStaked)
            // Assuming a reward pool (additional mechanism to be defined for actual pool management)
            v.Stake.Add(v.Stake, reward)
        }
    }
}

// InitializeBlockchain initializes a new instance of a blockchain
func InitializeBlockchain() *Blockchain {
    return &Blockchain{
        Validators: []*Validator{},
        TotalStaked: big.NewInt(0),
    }
}

func main() {
    blockchain := InitializeBlockchain()

    // Example usage
    validator := NewValidator("0x123", big.NewInt(1000), 180*24*time.Hour)
    blockchain.AddValidator(validator)
    validator.SlashValidator(1) // Low severity slashing

    if validator.CheckLockupPeriod() {
        println("Lockup period is over, the validator can unstake or withdraw.")
    }

    // Simulate reward distribution based on transaction volume
    transactionVolume := big.NewInt(10000) // Example transaction volume
    blockchain.RewardValidators(transactionVolume)
}
