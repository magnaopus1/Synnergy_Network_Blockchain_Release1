package transactions

import (
	"fmt"
	"sync"
	"time"

	"synnergy_network/core/tokens/token_standards/syn12/ledger"
	"synnergy_network/core/tokens/token_standards/syn12/storage"
)

// SaleHistoryManager manages the sale history of T-Bill tokens.
type SaleHistoryManager struct {
	ledger         *ledger.TransactionRecords
	storageManager *storage.StorageManager
	mu             sync.RWMutex
}

// NewSaleHistoryManager creates a new SaleHistoryManager.
func NewSaleHistoryManager(ledger *ledger.TransactionRecords, storageManager *storage.StorageManager) *SaleHistoryManager {
	return &SaleHistoryManager{
		ledger:         ledger,
		storageManager: storageManager,
	}
}

// RecordSale records a sale transaction in the ledger and storage.
func (shm *SaleHistoryManager) RecordSale(tokenID, seller, buyer string, salePrice float64) error {
	shm.mu.Lock()
	defer shm.mu.Unlock()

	// Create a sale record
	saleRecord := ledger.TransactionRecord{
		TokenID:      tokenID,
		From:         seller,
		To:           buyer,
		Amount:       salePrice,
		Timestamp:    time.Now().UTC(),
		TransactionType: "Sale",
	}

	// Record the sale in the ledger
	if err := shm.ledger.RecordTransaction(saleRecord); err != nil {
		return fmt.Errorf("failed to record sale in ledger: %v", err)
	}

	// Store the sale record in persistent storage
	if err := shm.storageManager.SaveData(fmt.Sprintf("sale_%s", tokenID), saleRecord); err != nil {
		return fmt.Errorf("failed to store sale record: %v", err)
	}

	return nil
}

// GetSaleHistory retrieves the sale history for a specific T-Bill token.
func (shm *SaleHistoryManager) GetSaleHistory(tokenID string) ([]ledger.TransactionRecord, error) {
	shm.mu.RLock()
	defer shm.mu.RUnlock()

	history, err := shm.ledger.GetTransactionHistory(tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve sale history: %v", err)
	}
	return history, nil
}

// VerifySale ensures that the sale transaction meets all the necessary criteria.
func (shm *SaleHistoryManager) VerifySale(tokenID, seller, buyer string) error {
	shm.mu.RLock()
	defer shm.mu.RUnlock()

	// Example verification: Ensure that the token is currently owned by the seller
	currentOwner, err := shm.ledger.GetOwner(tokenID)
	if err != nil {
		return fmt.Errorf("failed to get current owner: %v", err)
	}

	if currentOwner != seller {
		return fmt.Errorf("verification failed: seller does not own the token")
	}

	// Additional verifications can be implemented here

	return nil
}

// RetrieveSalesData provides a summary of all sales for analysis or reporting.
func (shm *SaleHistoryManager) RetrieveSalesData() (map[string][]ledger.TransactionRecord, error) {
	shm.mu.RLock()
	defer shm.mu.RUnlock()

	data, err := shm.ledger.GetAllTransactionRecords()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve sales data: %v", err)
	}

	// Filter only sale transactions
	salesData := make(map[string][]ledger.TransactionRecord)
	for tokenID, records := range data {
		for _, record := range records {
			if record.TransactionType == "Sale" {
				salesData[tokenID] = append(salesData[tokenID], record)
			}
		}
	}

	return salesData, nil
}
