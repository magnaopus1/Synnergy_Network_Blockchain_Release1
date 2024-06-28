package synthron_coin

import (
	"fmt"
	"time"

	"synnergy_network_blockchain/pkg/synnergy_network/core/transaction"
)

// GenesisBlock represents the initial block in the blockchain with allocation details
type GenesisBlock struct {
	Timestamp       time.Time
	InitialAllocations map[string]float64
}

// Wallet represents a simple wallet structure for holding Synthron Coins
type Wallet struct {
	Address string
	Balance float64
}

// initializeWallets sets up the initial wallets with predefined balances as per the genesis block.
func initializeWallets() map[string]*Wallet {
	return map[string]*Wallet{
		"genesisWallet":                 {Address: "genesisAddress", Balance: 5000000},
		"internalDevelopmentWallet":     {Address: "developmentAddress", Balance: 0},
		"externalCharitableWallet":      {Address: "charitableExternalAddress", Balance: 0},
		"internalCharitableWallet":      {Address: "charitableInternalAddress", Balance: 0},
		"loanPoolWallet":                {Address: "loanPoolAddress", Balance: 0},
		"passiveIncomeForHoldersWallet": {Address: "passiveIncomeAddress", Balance: 0},
		"nodeHostDistributionWallet":    {Address: "nodeHostAddress", Balance: 0},
		"creatorWallet":                 {Address: "creatorAddress", Balance: 0},
	}
}

// CreateGenesisBlock creates the initial block of the blockchain with allocations.
func CreateGenesisBlock() *GenesisBlock {
	wallets := initializeWallets()

	genesisBlock := &GenesisBlock{
		Timestamp: time.Now(),
		InitialAllocations: make(map[string]float64),
	}

	// Allocate initial coins to the genesis wallet
	genesisBlock.InitialAllocations[wallets["genesisWallet"].Address] = 5000000

	fmt.Println("Genesis Block Created with Initial Allocations:", genesisBlock.InitialAllocations)
	return genesisBlock
}

// DistributeInitialCoins handles the distribution of coins from the genesis block.
func DistributeInitialCoins(genesis *GenesisBlock, wallets map[string]*Wallet) {
	for address, amount := range genesis.InitialAllocations {
		if wallet, ok := wallets[address]; ok {
			wallet.Balance += amount
			fmt.Printf("Distributed %f Synthron Coins to %s\n", amount, address)
		}
	}
}