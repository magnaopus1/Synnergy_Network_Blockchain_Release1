package security

import (
	"encoding/json"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/layer0/core/blockchain"
	"github.com/synnergy_network/pkg/layer0/core/wallet"
	"golang.org/x/crypto/argon2"
)

// WalletFreezingService provides methods to freeze and unfreeze wallets
type WalletFreezingService struct {
	blockchainService *blockchain.BlockchainService
	walletService     *wallet.WalletService
	frozenWallets     sync.Map
	alerts            chan string
}

// NewWalletFreezingService initializes and returns a new WalletFreezingService
func NewWalletFreezingService(blockchainService *blockchain.BlockchainService, walletService *wallet.WalletService) *WalletFreezingService {
	return &WalletFreezingService{
		blockchainService: blockchainService,
		walletService:     walletService,
		alerts:            make(chan string, 100),
	}
}

// FreezeWallet freezes a wallet to prevent further transactions
func (wfs *WalletFreezingService) FreezeWallet(walletAddress string) error {
	if _, loaded := wfs.frozenWallets.LoadOrStore(walletAddress, true); loaded {
		return errors.New("wallet is already frozen")
	}

	wfs.blockchainService.AddTransactionFilter(walletAddress, wfs.transactionFilter)
	alertMsg := wfs.generateAlertMessage(walletAddress, "Wallet has been frozen")
	wfs.alerts <- alertMsg
	return nil
}

// UnfreezeWallet unfreezes a wallet to allow transactions
func (wfs *WalletFreezingService) UnfreezeWallet(walletAddress string) error {
	if _, loaded := wfs.frozenWallets.LoadAndDelete(walletAddress); !loaded {
		return errors.New("wallet is not frozen")
	}

	wfs.blockchainService.RemoveTransactionFilter(walletAddress)
	alertMsg := wfs.generateAlertMessage(walletAddress, "Wallet has been unfrozen")
	wfs.alerts <- alertMsg
	return nil
}

// IsWalletFrozen checks if a wallet is currently frozen
func (wfs *WalletFreezingService) IsWalletFrozen(walletAddress string) bool {
	_, frozen := wfs.frozenWallets.Load(walletAddress)
	return frozen
}

// transactionFilter is a filter applied to prevent transactions from frozen wallets
func (wfs *WalletFreezingService) transactionFilter(tx *blockchain.Transaction) bool {
	if wfs.IsWalletFrozen(tx.From) {
		log.Printf("Transaction from frozen wallet %s blocked", tx.From)
		return false
	}
	return true
}

// generateAlertMessage generates an alert message for wallet freezing or unfreezing
func (wfs *WalletFreezingService) generateAlertMessage(walletAddress string, action string) string {
	alert := map[string]interface{}{
		"message":      action,
		"wallet":       walletAddress,
		"time":         time.Now(),
		"alertType":    "WalletFreezing",
	}
	alertMsg, _ := json.Marshal(alert)
	return string(alertMsg)
}

// GetAlerts returns a channel to listen for freezing/unfreezing alerts
func (wfs *WalletFreezingService) GetAlerts() <-chan string {
	return wfs.alerts
}

// BlockchainService provides methods to interact with the blockchain
type BlockchainService struct {
	// ... existing methods and fields
	transactionFilters sync.Map // Map of transaction filters by wallet address
}

// AddTransactionFilter adds a transaction filter for a specific wallet address
func (bs *BlockchainService) AddTransactionFilter(walletAddress string, filter func(*blockchain.Transaction) bool) {
	bs.transactionFilters.Store(walletAddress, filter)
}

// RemoveTransactionFilter removes the transaction filter for a specific wallet address
func (bs *BlockchainService) RemoveTransactionFilter(walletAddress string) {
	bs.transactionFilters.Delete(walletAddress)
}

// WalletService provides methods to manage wallet functionalities
type WalletService struct {
	// ... existing methods and fields
}

// Transaction represents a simplified transaction structure for the blockchain
type Transaction struct {
	From   string
	To     string
	Amount float64
	Time   time.Time
}

func main() {
	// Simulating dependency initialization
	blockchainService := &blockchain.BlockchainService{}
	walletService := &wallet.WalletService{}
	walletFreezingService := NewWalletFreezingService(blockchainService, walletService)

	// Simulating freezing a wallet
	walletAddress := "address1"
	err := walletFreezingService.FreezeWallet(walletAddress)
	if err != nil {
		log.Printf("Error freezing wallet: %v", err)
	} else {
		log.Printf("Wallet %s has been frozen", walletAddress)
	}

	// Simulating unfreezing a wallet
	err = walletFreezingService.UnfreezeWallet(walletAddress)
	if err != nil {
		log.Printf("Error unfreezing wallet: %v", err)
	} else {
		log.Printf("Wallet %s has been unfrozen", walletAddress)
	}

	// Listen for alerts
	for alert := range walletFreezingService.GetAlerts() {
		log.Printf("Alert: %s", alert)
	}
}
