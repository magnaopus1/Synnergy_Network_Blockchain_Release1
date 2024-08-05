package transactions

import (
    "time"
    "errors"
    "sync"
)

// SaleRecord represents a record of a token sale
type SaleRecord struct {
    TokenID     string
    Seller      string
    Buyer       string
    Amount      uint64
    SalePrice   float64
    SaleDate    time.Time
}

// SaleHistory manages the history of token sales
type SaleHistory struct {
    records map[string][]SaleRecord
    mu      sync.RWMutex
}

// NewSaleHistory creates a new SaleHistory instance
func NewSaleHistory() *SaleHistory {
    return &SaleHistory{
        records: make(map[string][]SaleRecord),
    }
}

// AddRecord adds a new sale record to the history
func (sh *SaleHistory) AddRecord(tokenID, seller, buyer string, amount uint64, salePrice float64) error {
    if tokenID == "" || seller == "" || buyer == "" || amount == 0 || salePrice <= 0 {
        return errors.New("invalid sale record parameters")
    }

    sh.mu.Lock()
    defer sh.mu.Unlock()

    record := SaleRecord{
        TokenID:   tokenID,
        Seller:    seller,
        Buyer:     buyer,
        Amount:    amount,
        SalePrice: salePrice,
        SaleDate:  time.Now(),
    }

    sh.records[tokenID] = append(sh.records[tokenID], record)
    return nil
}

// GetRecords retrieves the sale records for a specific token
func (sh *SaleHistory) GetRecords(tokenID string) ([]SaleRecord, error) {
    sh.mu.RLock()
    defer sh.mu.RUnlock()

    if records, exists := sh.records[tokenID]; exists {
        return records, nil
    }

    return nil, errors.New("no sale records found for the specified token ID")
}

// GetAllRecords retrieves all sale records
func (sh *SaleHistory) GetAllRecords() map[string][]SaleRecord {
    sh.mu.RLock()
    defer sh.mu.RUnlock()

    // Create a deep copy of records to avoid data races
    recordsCopy := make(map[string][]SaleRecord)
    for tokenID, records := range sh.records {
        recordsCopy[tokenID] = append([]SaleRecord(nil), records...)
    }

    return recordsCopy
}

// GetRecordsBySeller retrieves sale records for a specific seller
func (sh *SaleHistory) GetRecordsBySeller(seller string) ([]SaleRecord, error) {
    sh.mu.RLock()
    defer sh.mu.RUnlock()

    var results []SaleRecord
    for _, records := range sh.records {
        for _, record := range records {
            if record.Seller == seller {
                results = append(results, record)
            }
        }
    }

    if len(results) == 0 {
        return nil, errors.New("no sale records found for the specified seller")
    }

    return results, nil
}

// GetRecordsByBuyer retrieves sale records for a specific buyer
func (sh *SaleHistory) GetRecordsByBuyer(buyer string) ([]SaleRecord, error) {
    sh.mu.RLock()
    defer sh.mu.RUnlock()

    var results []SaleRecord
    for _, records := range sh.records {
        for _, record := range records {
            if record.Buyer == buyer {
                results = append(results, record)
            }
        }
    }

    if len(results) == 0 {
        return nil, errors.New("no sale records found for the specified buyer")
    }

    return results, nil
}
