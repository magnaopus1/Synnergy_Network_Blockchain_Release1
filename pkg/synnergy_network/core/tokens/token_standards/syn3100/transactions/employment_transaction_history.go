package transactions

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
)

// EmploymentTransactionHistory manages the transaction history for employment tokens
type EmploymentTransactionHistory struct {
	historyPath   string
	security      *security.SecurityManager
	encryptionKey []byte
	ledger        *ledger.TransactionLedger
}

// NewEmploymentTransactionHistory initializes a new EmploymentTransactionHistory instance
func NewEmploymentTransactionHistory(historyPath string, security *security.SecurityManager, encryptionKey []byte, ledger *ledger.TransactionLedger) (*EmploymentTransactionHistory, error) {
	if len(encryptionKey) == 0 {
		return nil, errors.New("encryption key cannot be empty")
	}

	history := &EmploymentTransactionHistory{
		historyPath:   historyPath,
		security:      security,
		encryptionKey: encryptionKey,
		ledger:        ledger,
	}

	return history, nil
}

// TransactionRecord represents a single transaction record
type TransactionRecord struct {
	TransactionID string    `json:"transaction_id"`
	EmployeeID    string    `json:"employee_id"`
	EmployerID    string    `json:"employer_id"`
	ContractID    string    `json:"contract_id"`
	Timestamp     time.Time `json:"timestamp"`
	Details       string    `json:"details"`
}

// SaveTransactionRecord saves a transaction record to the history
func (eth *EmploymentTransactionHistory) SaveTransactionRecord(record *TransactionRecord) error {
	records, err := eth.LoadTransactionHistory()
	if err != nil {
		return fmt.Errorf("failed to load transaction history: %w", err)
	}

	records = append(records, *record)
	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction records: %w", err)
	}

	encryptedData, err := eth.security.Encrypt(data, eth.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt transaction data: %w", err)
	}

	err = os.WriteFile(eth.historyPath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write transaction data to history: %w", err)
	}

	return nil
}

// LoadTransactionHistory loads the transaction history
func (eth *EmploymentTransactionHistory) LoadTransactionHistory() ([]TransactionRecord, error) {
	var records []TransactionRecord

	encryptedData, err := os.ReadFile(eth.historyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return records, nil
		}
		return nil, fmt.Errorf("failed to read transaction history: %w", err)
	}

	data, err := eth.security.Decrypt(encryptedData, eth.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt transaction data: %w", err)
	}

	err = json.Unmarshal(data, &records)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal transaction records: %w", err)
	}

	return records, nil
}

// GetTransactionByID retrieves a transaction record by ID
func (eth *EmploymentTransactionHistory) GetTransactionByID(transactionID string) (*TransactionRecord, error) {
	records, err := eth.LoadTransactionHistory()
	if err != nil {
		return nil, fmt.Errorf("failed to load transaction history: %w", err)
	}

	for _, record := range records {
		if record.TransactionID == transactionID {
			return &record, nil
		}
	}

	return nil, errors.New("transaction not found")
}

// GetTransactionsByEmployeeID retrieves all transaction records for a specific employee
func (eth *EmploymentTransactionHistory) GetTransactionsByEmployeeID(employeeID string) ([]TransactionRecord, error) {
	var employeeRecords []TransactionRecord

	records, err := eth.LoadTransactionHistory()
	if err != nil {
		return nil, fmt.Errorf("failed to load transaction history: %w", err)
	}

	for _, record := range records {
		if record.EmployeeID == employeeID {
			employeeRecords = append(employeeRecords, record)
		}
	}

	return employeeRecords, nil
}

// GetTransactionsByEmployerID retrieves all transaction records for a specific employer
func (eth *EmploymentTransactionHistory) GetTransactionsByEmployerID(employerID string) ([]TransactionRecord, error) {
	var employerRecords []TransactionRecord

	records, err := eth.LoadTransactionHistory()
	if err != nil {
		return nil, fmt.Errorf("failed to load transaction history: %w", err)
	}

	for _, record := range records {
		if record.EmployerID == employerID {
			employerRecords = append(employerRecords, record)
		}
	}

	return employerRecords, nil
}

// GetTransactionsByContractID retrieves all transaction records for a specific contract
func (eth *EmploymentTransactionHistory) GetTransactionsByContractID(contractID string) ([]TransactionRecord, error) {
	var contractRecords []TransactionRecord

	records, err := eth.LoadTransactionHistory()
	if err != nil {
		return nil, fmt.Errorf("failed to load transaction history: %w", err)
	}

	for _, record := range records {
		if record.ContractID == contractID {
			contractRecords = append(contractRecords, record)
		}
	}

	return contractRecords, nil
}

// RemoveTransactionRecord removes a transaction record by ID
func (eth *EmploymentTransactionHistory) RemoveTransactionRecord(transactionID string) error {
	records, err := eth.LoadTransactionHistory()
	if err != nil {
		return fmt.Errorf("failed to load transaction history: %w", err)
	}

	for i, record := range records {
		if record.TransactionID == transactionID {
			records = append(records[:i], records[i+1:]...)
			break
		}
	}

	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction records: %w", err)
	}

	encryptedData, err := eth.security.Encrypt(data, eth.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt transaction data: %w", err)
	}

	err = os.WriteFile(eth.historyPath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write transaction data to history: %w", err)
	}

	return nil
}

// ListAllTransactions lists all transactions in the history
func (eth *EmploymentTransactionHistory) ListAllTransactions() ([]TransactionRecord, error) {
	return eth.LoadTransactionHistory()
}
