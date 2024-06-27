package synthron_coin

import (
	"errors"
	"time"
)

// Wallet struct to represent a wallet in the system
type Wallet struct {
	Address string
	Balance float64
}

// Distribution struct to hold all distribution wallets
type Distribution struct {
	GenesisWallet                Wallet
	InternalDevelopmentWallet    Wallet
	ExternalCharitableWallet     Wallet
	InternalCharitableWallet     Wallet
	LoanPoolWallet               Wallet
	PassiveIncomeWallet          Wallet
	NodeHostDistributionWallet   Wallet
	CreatorWallet                Wallet
}

// InitialSetup struct to hold the initial setup information
type InitialSetup struct {
	GenesisBlockCreated bool
	InitialGenesisBlockTimestamp time.Time
	Distribution         Distribution
	TotalSupply          float64
}

// NewInitialSetup initializes a new InitialSetup structure.
func NewInitialSetup(totalSupply float64) *InitialSetup {
	return &InitialSetup{
		GenesisBlockCreated:         false,
		InitialGenesisBlockTimestamp: time.Time{},
		Distribution: Distribution{
			GenesisWallet:                Wallet{Address: "genesis_wallet", Balance: 5000000},
			InternalDevelopmentWallet:    Wallet{Address: "internal_dev_wallet", Balance: 0},
			ExternalCharitableWallet:     Wallet{Address: "external_charity_wallet", Balance: 0},
			InternalCharitableWallet:     Wallet{Address: "internal_charity_wallet", Balance: 0},
			LoanPoolWallet:               Wallet{Address: "loan_pool_wallet", Balance: 0},
			PassiveIncomeWallet:          Wallet{Address: "passive_income_wallet", Balance: 0},
			NodeHostDistributionWallet:   Wallet{Address: "node_host_wallet", Balance: 0},
			CreatorWallet:                Wallet{Address: "creator_wallet", Balance: 0},
		},
		TotalSupply: totalSupply,
	}
}

// CreateGenesisBlock creates the genesis block with initial distribution.
func (is *InitialSetup) CreateGenesisBlock() error {
	if is.GenesisBlockCreated {
		return errors.New("genesis block already created")
	}

	is.InitialGenesisBlockTimestamp = time.Now()
	is.GenesisBlockCreated = true

	return nil
}

// AllocateFunds allocates funds to the respective wallets after genesis block creation.
func (is *InitialSetup) AllocateFunds() error {
	if !is.GenesisBlockCreated {
		return errors.New("genesis block not created")
	}

	is.Distribution.InternalDevelopmentWallet.Balance = is.TotalSupply * 0.1
	is.Distribution.ExternalCharitableWallet.Balance = is.TotalSupply * 0.05
	is.Distribution.InternalCharitableWallet.Balance = is.TotalSupply * 0.05
	is.Distribution.LoanPoolWallet.Balance = is.TotalSupply * 0.1
	is.Distribution.PassiveIncomeWallet.Balance = is.TotalSupply * 0.1
	is.Distribution.NodeHostDistributionWallet.Balance = is.TotalSupply * 0.1
	is.Distribution.CreatorWallet.Balance = is.TotalSupply * 0.1

	return nil
}

// CheckBalances checks the balances of all wallets.
func (is *InitialSetup) CheckBalances() map[string]float64 {
	balances := make(map[string]float64)
	balances["Genesis Wallet"] = is.Distribution.GenesisWallet.Balance
	balances["Internal Development Wallet"] = is.Distribution.InternalDevelopmentWallet.Balance
	balances["External Charitable Wallet"] = is.Distribution.ExternalCharitableWallet.Balance
	balances["Internal Charitable Wallet"] = is.Distribution.InternalCharitableWallet.Balance
	balances["Loan Pool Wallet"] = is.Distribution.LoanPoolWallet.Balance
	balances["Passive Income Wallet"] = is.Distribution.PassiveIncomeWallet.Balance
	balances["Node Host Distribution Wallet"] = is.Distribution.NodeHostDistributionWallet.Balance
	balances["Creator Wallet"] = is.Distribution.CreatorWallet.Balance

	return balances
}

// TransferFunds transfers funds from one wallet to another
func (is *InitialSetup) TransferFunds(fromWallet, toWallet *Wallet, amount float64) error {
	if fromWallet.Balance < amount {
		return errors.New("insufficient funds")
	}

	fromWallet.Balance -= amount
	toWallet.Balance += amount
	return nil
}
