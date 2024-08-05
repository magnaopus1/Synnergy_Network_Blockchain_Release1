package transactions

import (
	"fmt"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn223/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/utils"
)

// SaleRecord represents a record of a token sale
type SaleRecord struct {
	TokenID      string
	Seller       string
	Buyer        string
	Price        float64
	Timestamp    time.Time
	TransactionID string
}

// SaleHistory stores the sale history of tokens
type SaleHistory struct {
	records map[string][]SaleRecord
	Ledger  *ledger.Ledger
}

// NewSaleHistory initializes a new SaleHistory instance
func NewSaleHistory(ledger *ledger.Ledger) *SaleHistory {
	return &SaleHistory{
		records: make(map[string][]SaleRecord),
		Ledger:  ledger,
	}
}

// AddSaleRecord adds a new sale record to the history
func (sh *SaleHistory) AddSaleRecord(tokenID, seller, buyer string, price float64) error {
	if !sh.Ledger.IsValidToken(tokenID) {
		return fmt.Errorf("invalid token ID: %s", tokenID)
	}

	record := SaleRecord{
		TokenID:      tokenID,
		Seller:       seller,
		Buyer:        buyer,
		Price:        price,
		Timestamp:    time.Now(),
		TransactionID: utils.GenerateTransactionID(),
	}

	sh.records[tokenID] = append(sh.records[tokenID], record)
	return sh.Ledger.LogSaleRecord(record)
}

// GetSaleHistory returns the sale history for a specific token
func (sh *SaleHistory) GetSaleHistory(tokenID string) ([]SaleRecord, error) {
	if !sh.Ledger.IsValidToken(tokenID) {
		return nil, fmt.Errorf("invalid token ID: %s", tokenID)
	}

	history, exists := sh.records[tokenID]
	if !exists {
		return nil, fmt.Errorf("no sale history found for token ID: %s", tokenID)
	}

	return history, nil
}

// SaleHistoryManager handles the sale history operations
type SaleHistoryManager struct {
	SaleHistory *SaleHistory
}

// NewSaleHistoryManager initializes a new SaleHistoryManager instance
func NewSaleHistoryManager(saleHistory *SaleHistory) *SaleHistoryManager {
	return &SaleHistoryManager{
		SaleHistory: saleHistory,
	}
}

// RecordSaleTransaction records a token sale transaction
func (shm *SaleHistoryManager) RecordSaleTransaction(tokenID, seller, buyer string, price float64) error {
	return shm.SaleHistory.AddSaleRecord(tokenID, seller, buyer, price)
}

// RetrieveSaleHistory retrieves the sale history of a token
func (shm *SaleHistoryManager) RetrieveSaleHistory(tokenID string) ([]SaleRecord, error) {
	return shm.SaleHistory.GetSaleHistory(tokenID)
}
