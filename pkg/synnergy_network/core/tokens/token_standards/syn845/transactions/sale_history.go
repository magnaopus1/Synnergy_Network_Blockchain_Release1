package transactions

import (
	"errors"
	"sync"
	"time"
)

// SaleRecord represents a record of a sale or transfer of a debt instrument
type SaleRecord struct {
	Date          time.Time
	From          string
	To            string
	Amount        float64
	InstrumentID  string
	TransactionID string
}

// DebtInstrumentWithSaleHistory extends DebtInstrument to include sale history
type DebtInstrumentWithSaleHistory struct {
	DebtInstrument
	SaleHistory []SaleRecord
}

// SaleHistoryHandler manages the sale histories of debt instruments
type SaleHistoryHandler struct {
	debts map[string]*DebtInstrumentWithSaleHistory
	mu    sync.RWMutex
}

// NewSaleHistoryHandler creates a new SaleHistoryHandler instance
func NewSaleHistoryHandler() *SaleHistoryHandler {
	return &SaleHistoryHandler{
		debts: make(map[string]*DebtInstrumentWithSaleHistory),
	}
}

// AddDebtInstrument adds a new debt instrument to the manager with sale history tracking
func (sh *SaleHistoryHandler) AddDebtInstrument(id, owner string, principal, interestRate float64, originalTerm int, nextPaymentDate time.Time) {
	sh.mu.Lock()
	defer sh.mu.Unlock()

	sh.debts[id] = &DebtInstrumentWithSaleHistory{
		DebtInstrument: DebtInstrument{
			ID:              id,
			Owner:           owner,
			Principal:       principal,
			InterestRate:    interestRate,
			OriginalTerm:    originalTerm,
			RemainingTerm:   originalTerm,
			NextPaymentDate: nextPaymentDate,
			Status:          "active",
		},
		SaleHistory: []SaleRecord{},
	}
}

// RecordSale records a sale or transfer of a debt instrument
func (sh *SaleHistoryHandler) RecordSale(instrumentID, from, to string, amount float64, transactionID string) error {
	sh.mu.Lock()
	defer sh.mu.Unlock()

	debt, exists := sh.debts[instrumentID]
	if !exists {
		return errors.New("debt instrument not found")
	}

	saleRecord := SaleRecord{
		Date:          time.Now(),
		From:          from,
		To:            to,
		Amount:        amount,
		InstrumentID:  instrumentID,
		TransactionID: transactionID,
	}

	debt.SaleHistory = append(debt.SaleHistory, saleRecord)
	debt.Owner = to

	return nil
}

// GetSaleHistory returns the sale history of a debt instrument by ID
func (sh *SaleHistoryHandler) GetSaleHistory(instrumentID string) ([]SaleRecord, error) {
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	debt, exists := sh.debts[instrumentID]
	if !exists {
		return nil, errors.New("debt instrument not found")
	}

	return debt.SaleHistory, nil
}

// GetDebtInstrument returns a debt instrument with sale history by ID
func (sh *SaleHistoryHandler) GetDebtInstrument(instrumentID string) (*DebtInstrumentWithSaleHistory, error) {
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	debt, exists := sh.debts[instrumentID]
	if !exists {
		return nil, errors.New("debt instrument not found")
	}

	return debt, nil
}

