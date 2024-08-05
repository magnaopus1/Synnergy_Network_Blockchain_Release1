package syn3300

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/events"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/factory"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/fractional_ownership"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/integration"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/management"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/smart_contracts"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/storage"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/transactions"
)

// Syn3300Token represents a SYN3300 token with full details
type Syn3300Token struct {
	ID          string
	Name        string
	TotalSupply float64
	ETFDetails  assets.ETF
	Value       float64
}

// NewSyn3300Token creates a new instance of Syn3300Token
func NewSyn3300Token(id, name string, totalSupply, value float64, etfDetails assets.ETF) *Syn3300Token {
	return &Syn3300Token{
		ID:          id,
		Name:        name,
		TotalSupply: totalSupply,
		ETFDetails:  etfDetails,
		Value:       value,
	}
}

// SYN3300 represents the SYN3300 token standard
type SYN3300 struct {
	Factory            *factory.TokenFactory
	StorageManager     *storage.StorageManager
	LedgerManager      *ledger.LedgerManager
	FractionalManager  *fractional_ownership.FractionalOwnershipManager
	SmartContractMgr   *smart_contracts.SmartContractManager
	ManagementManager  *management.ManagementManager
	IntegrationManager *integration.IntegrationManager
	EventsManager      *events.EventsManager
	Tokens             map[string]*Syn3300Token
}

// NewSYN3300 creates a new instance of SYN3300
func NewSYN3300() *SYN3300 {
	return &SYN3300{
		Factory:            factory.NewTokenFactory(),
		StorageManager:     storage.NewStorageManager(),
		LedgerManager:      ledger.NewLedgerManager(),
		FractionalManager:  fractional_ownership.NewFractionalOwnershipManager(),
		SmartContractMgr:   smart_contracts.NewSmartContractManager(),
		ManagementManager:  management.NewManagementManager(),
		IntegrationManager: integration.NewIntegrationManager(),
		EventsManager:      events.NewEventsManager(),
		Tokens:             make(map[string]*Syn3300Token),
	}
}

// CreateETF creates a new ETF with the specified parameters
func (s *SYN3300) CreateETF(etfID, name string, totalShares, initialPrice float64) error {
	etf := assets.NewETF(etfID, name, totalShares, initialPrice)
	token := NewSyn3300Token(etfID, name, totalShares, initialPrice, *etf)
	s.Tokens[etfID] = token

	err := s.Factory.CreateToken(etf)
	if err != nil {
		return fmt.Errorf("failed to create ETF: %v", err)
	}

	err = s.StorageManager.SaveETF(etf)
	if err != nil {
		return fmt.Errorf("failed to save ETF: %v", err)
	}

	return nil
}

// TransferShares transfers shares from one address to another
func (s *SYN3300) TransferShares(fromAddress, toAddress, etfID string, shares float64) error {
	transactionID := generateTransactionID(fromAddress, toAddress, etfID, shares, time.Now())
	transaction := transactions.NewETFTransaction(transactionID, fromAddress, toAddress, etfID, shares)

	validator := transactions.NewTransactionValidator(s.LedgerManager, s.StorageManager)
	valid, err := validator.ValidateTransaction(transactionID)
	if err != nil {
		return fmt.Errorf("transaction validation failed: %v", err)
	}

	if !valid {
		return errors.New("transaction is invalid")
	}

	err = s.LedgerManager.RecordTransaction(transaction)
	if err != nil {
		return fmt.Errorf("failed to record transaction: %v", err)
	}

	err = s.StorageManager.UpdateOwnership(transaction)
	if err != nil {
		return fmt.Errorf("failed to update ownership: %v", err)
	}

	s.EventsManager.Emit(events.NewTransferEvent(transactionID, fromAddress, toAddress, etfID, shares))
	return nil
}

// generateTransactionID generates a unique ID for a transaction
func generateTransactionID(fromAddress, toAddress, etfID string, shares float64, timestamp time.Time) string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%v%v%v%v%v", fromAddress, toAddress, etfID, shares, timestamp)))
	return hex.EncodeToString(hash.Sum(nil))
}

// DistributeDividends distributes dividends to ETF share token holders
func (s *SYN3300) DistributeDividends(etfID string, totalDividend float64) error {
	owners, err := s.LedgerManager.GetOwners(etfID)
	if err != nil {
		return fmt.Errorf("failed to get owners: %v", err)
	}

	dividendPerShare := totalDividend / s.LedgerManager.GetTotalShares(etfID)

	for owner, shares := range owners {
		dividend := shares * dividendPerShare
		err = s.TransferShares("", owner, etfID, dividend)
		if err != nil {
			return fmt.Errorf("failed to distribute dividends: %v", err)
		}
	}

	return nil
}

// MintNewShares mints new shares for an existing ETF
func (s *SYN3300) MintNewShares(etfID string, additionalShares float64) error {
	err := s.Factory.MintShares(etfID, additionalShares)
	if err != nil {
		return fmt.Errorf("failed to mint new shares: %v", err)
	}

	err = s.StorageManager.UpdateTotalShares(etfID, additionalShares)
	if err != nil {
		return fmt.Errorf("failed to update total shares: %v", err)
	}

	// Update the token's total supply
	if token, exists := s.Tokens[etfID]; exists {
		token.TotalSupply += additionalShares
	} else {
		return errors.New("token not found")
	}

	return nil
}

// BurnShares burns a specified amount of shares for an existing ETF
func (s *SYN3300) BurnShares(etfID string, sharesToBurn float64) error {
	err := s.Factory.BurnShares(etfID, sharesToBurn)
	if err != nil {
		return fmt.Errorf("failed to burn shares: %v", err)
	}

	err = s.StorageManager.UpdateTotalShares(etfID, -sharesToBurn)
	if err != nil {
		return fmt.Errorf("failed to update total shares: %v", err)
	}

	// Update the token's total supply
	if token, exists := s.Tokens[etfID]; exists {
		token.TotalSupply -= sharesToBurn
	} else {
		return errors.New("token not found")
	}

	return nil
}

// MonitorETFPrice continuously monitors the price of an ETF and triggers automated actions
func (s *SYN3300) MonitorETFPrice(etfID string) {
	go func() {
		for {
			price, err := s.SmartContractMgr.GetCurrentPrice(etfID)
			if err != nil {
				fmt.Printf("failed to get current price: %v\n", err)
				continue
			}

			// Update the token's value
			if token, exists := s.Tokens[etfID]; exists {
				token.Value = price
			} else {
				fmt.Printf("token not found for etfID: %v\n", etfID)
			}

			time.Sleep(1 * time.Minute) // Adjust the sleep duration as needed
		}
	}()
}

// GetTokenDetails returns the details of a specific SYN3300 token
func (s *SYN3300) GetTokenDetails(etfID string) (*Syn3300Token, error) {
	token, exists := s.Tokens[etfID]
	if !exists {
		return nil, errors.New("token not found")
	}
	return token, nil
}
