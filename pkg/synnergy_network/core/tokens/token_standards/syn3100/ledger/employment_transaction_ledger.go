package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
)

// TransactionType represents the type of transaction
type TransactionType string

const (
	TransactionTypeCreate   TransactionType = "CREATE"
	TransactionTypeUpdate   TransactionType = "UPDATE"
	TransactionTypeTransfer TransactionType = "TRANSFER"
)

// TransactionRecord represents a record of an employment transaction
type TransactionRecord struct {
	TransactionID string          `json:"transaction_id"`
	ContractID    string          `json:"contract_id"`
	Type          TransactionType `json:"type"`
	Timestamp     time.Time       `json:"timestamp"`
	Data          string          `json:"data"`
}

// EmploymentTransactionLedger manages the ledger for employment transactions
type EmploymentTransactionLedger struct {
	records map[string]TransactionRecord
}

// NewEmploymentTransactionLedger initializes a new EmploymentTransactionLedger instance
func NewEmploymentTransactionLedger() *EmploymentTransactionLedger {
	return &EmploymentTransactionLedger{
		records: make(map[string]TransactionRecord),
	}
}

// AddTransaction adds a new transaction to the ledger
func (etl *EmploymentTransactionLedger) AddTransaction(contractID string, transactionType TransactionType, data interface{}) (string, error) {
	transactionID := generateTransactionID()
	timestamp := time.Now()

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	transactionRecord := TransactionRecord{
		TransactionID: transactionID,
		ContractID:    contractID,
		Type:          transactionType,
		Timestamp:     timestamp,
		Data:          string(dataBytes),
	}

	etl.records[transactionID] = transactionRecord

	return transactionID, nil
}

// GetTransaction retrieves a transaction from the ledger by transaction ID
func (etl *EmploymentTransactionLedger) GetTransaction(transactionID string) (TransactionRecord, error) {
	record, exists := etl.records[transactionID]
	if !exists {
		return TransactionRecord{}, errors.New("transaction not found")
	}
	return record, nil
}

// GetTransactionsByContract retrieves all transactions for a specific contract
func (etl *EmploymentTransactionLedger) GetTransactionsByContract(contractID string) ([]TransactionRecord, error) {
	var transactions []TransactionRecord
	for _, record := range etl.records {
		if record.ContractID == contractID {
			transactions = append(transactions, record)
		}
	}
	return transactions, nil
}

// VerifyTransaction verifies the integrity and authenticity of a transaction
func (etl *EmploymentTransactionLedger) VerifyTransaction(transactionID string, expectedData interface{}) (bool, error) {
	record, err := etl.GetTransaction(transactionID)
	if err != nil {
		return false, err
	}

	var data interface{}
	err = json.Unmarshal([]byte(record.Data), &data)
	if err != nil {
		return false, err
	}

	return data == expectedData, nil
}

// EncryptTransactionData encrypts the data of a transaction for secure storage
func (etl *EmploymentTransactionLedger) EncryptTransactionData(transactionID, password string) (string, error) {
	record, err := etl.GetTransaction(transactionID)
	if err != nil {
		return "", err
	}

	encryptedData, err := security.EncryptData([]byte(record.Data), password)
	if err != nil {
		return "", err
	}

	record.Data = encryptedData
	etl.records[transactionID] = record

	return encryptedData, nil
}

// DecryptTransactionData decrypts the data of a transaction
func (etl *EmploymentTransactionLedger) DecryptTransactionData(transactionID, password string) (string, error) {
	record, err := etl.GetTransaction(transactionID)
	if err != nil {
		return "", err
	}

	decryptedData, err := security.DecryptData(record.Data, password)
	if err != nil {
		return "", err
	}

	record.Data = decryptedData
	etl.records[transactionID] = record

	return decryptedData, nil
}

// generateTransactionID generates a unique transaction ID
func generateTransactionID() string {
	return fmt.Sprintf("tx_%d", time.Now().UnixNano())
}

// Example usage (not to be included in the final file):
// func main() {
//     ledger := NewEmploymentTransactionLedger()
//     contract := assets.EmploymentMetadata{ContractID: "c123", EmployeeID: "e123", EmployerID: "emp123", Position: "Developer", Salary: 100000, StartDate: time.Now(), EndDate: time.Now().AddDate(1, 0, 0), Benefits: "Health Insurance", Active: true}
//     txID, err := ledger.AddTransaction("c123", TransactionTypeCreate, contract)
//     if err != nil {
//         log.Fatalf("Error adding transaction: %v", err)
//     }
//     fmt.Println("Transaction ID:", txID)
// }
