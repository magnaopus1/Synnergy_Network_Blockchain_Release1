package synthron_coin

import (
	"fmt"
	"log"
	"os"

	"github.com/pkg/errors"
)

// Logger setup for the application.
var logger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)

// GenesisBlock represents the initial block in the blockchain with a special transaction.
type GenesisBlock struct {
	InitialCoins   float64
	CreatorsWallet string
}

// CoinDistributionManager manages the distribution and initial setup of Synthron Coins.
type CoinDistributionManager struct {
	genesisBlock GenesisBlock
	totalSupply  float64
	maxSupply    float64
}

// NewCoinDistributionManager initializes the manager with genesis block and supply details.
func NewCoinDistributionManager(initialCoins float64, creatorsWallet string, maxSupply float64) *CoinDistributionManager {
	return &CoinDistributionManager{
		genesisBlock: GenesisBlock{
			InitialCoins:   initialCoins,
			CreatorsWallet: creatorsWallet,
		},
		totalSupply: initialCoins,
		maxSupply:   maxSupply,
	}
}

// SetupGenesisBlock simulates the creation of the genesis block.
func (m *CoinDistributionManager) SetupGenesisBlock() error {
	if m.totalSupply > m.maxSupply {
		return errors.New("initial supply exceeds maximum supply limit")
	}
	logger.Printf("Genesis block created with %f Synthron Coins allocated to %s\n", m.genesisBlock.InitialCoins, m.genesisBlock.CreatorsWallet)
	return nil
}

// CalculateInitialPrice computes the initial market price of Synthron based on various economic factors.
func (m *CoinDistributionManager) CalculateInitialPrice(costOfProduction, regulatoryCosts, marketAvgPrice, valueMultiplier, tokenomicsFactor, communityInput float64) float64 {
	initialPrice := (costOfProduction + regulatoryCosts + ((marketAvgPrice * valueMultiplier) / tokenomicsFactor)) * communityInput
	return initialPrice
}

func main() {
	// Initialize logging
	logger.SetOutput(os.Stdout)

	// Example setup and initial price calculation
	manager := NewCoinDistributionManager(5000000, "CreatorsWalletAddress", 500000000)
	if err := manager.SetupGenesisBlock(); err != nil {
		logger.Printf("Error setting up the genesis block: %v\n", err)
		return
	}

	// Hypothetical economic factors for price calculation
	costOfProduction := 1.0 // Hypothetical cost
	regulatoryCosts := 0.5  // Hypothetical regulatory costs
	marketAvgPrice := 2.0   // Average market price of comparable coins
	valueMultiplier := 1.2  // Value based on technology and usability
	tokenomicsFactor := 1.1 // Token supply/demand adjustment factor
	communityInput := 1.05  // Community and ecosystem feedback factor

	initialPrice := manager.CalculateInitialPrice(costOfProduction, regulatoryCosts, marketAvgPrice, valueMultiplier, tokenomicsFactor, communityInput)
	logger.Printf("Calculated Initial Price of Synthron Coin: $%.2f\n", initialPrice)
}
