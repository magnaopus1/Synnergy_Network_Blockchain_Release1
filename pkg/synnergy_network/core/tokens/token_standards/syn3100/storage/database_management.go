package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
)

// DatabaseManager manages the database operations for SYN3100 tokens
type DatabaseManager struct {
	db       *sql.DB
	security *security.SecurityManager
}

// NewDatabaseManager initializes a new DatabaseManager instance
func NewDatabaseManager(dbPath string, security *security.SecurityManager) (*DatabaseManager, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	manager := &DatabaseManager{
		db:       db,
		security: security,
	}

	err = manager.setupDatabase()
	if err != nil {
		return nil, err
	}

	return manager, nil
}

// setupDatabase sets up the necessary database tables
func (dm *DatabaseManager) setupDatabase() error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS employment_contracts (
			contract_id TEXT PRIMARY KEY,
			employee_id TEXT,
			employer_id TEXT,
			position TEXT,
			salary REAL,
			contract_type TEXT,
			start_date TEXT,
			end_date TEXT,
			benefits TEXT,
			contract_terms TEXT,
			active_status BOOLEAN
		);`,
		`CREATE TABLE IF NOT EXISTS transactions (
			transaction_id TEXT PRIMARY KEY,
			contract_id TEXT,
			timestamp TEXT,
			amount REAL,
			transaction_type TEXT,
			status TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS smart_contracts (
			contract_id TEXT PRIMARY KEY,
			token_id TEXT,
			issuer_id TEXT,
			code TEXT,
			creation_date TEXT
		);`,
	}

	for _, table := range tables {
		_, err := dm.db.Exec(table)
		if err != nil {
			return err
		}
	}
	return nil
}

// AddEmploymentContract adds a new employment contract to the database
func (dm *DatabaseManager) AddEmploymentContract(contract *EmploymentContract) error {
	stmt, err := dm.db.Prepare(`INSERT INTO employment_contracts (
		contract_id, employee_id, employer_id, position, salary, contract_type, start_date, end_date, benefits, contract_terms, active_status
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(contract.ContractID, contract.EmployeeID, contract.EmployerID, contract.Position, contract.Salary, contract.ContractType, contract.StartDate, contract.EndDate, contract.Benefits, contract.ContractTerms, contract.ActiveStatus)
	return err
}

// GetEmploymentContract retrieves an employment contract from the database by contract ID
func (dm *DatabaseManager) GetEmploymentContract(contractID string) (*EmploymentContract, error) {
	stmt, err := dm.db.Prepare(`SELECT contract_id, employee_id, employer_id, position, salary, contract_type, start_date, end_date, benefits, contract_terms, active_status FROM employment_contracts WHERE contract_id = ?;`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	contract := &EmploymentContract{}
	err = stmt.QueryRow(contractID).Scan(&contract.ContractID, &contract.EmployeeID, &contract.EmployerID, &contract.Position, &contract.Salary, &contract.ContractType, &contract.StartDate, &contract.EndDate, &contract.Benefits, &contract.ContractTerms, &contract.ActiveStatus)
	if err != nil {
		return nil, err
	}

	return contract, nil
}

// UpdateEmploymentContract updates an existing employment contract in the database
func (dm *DatabaseManager) UpdateEmploymentContract(contract *EmploymentContract) error {
	stmt, err := dm.db.Prepare(`UPDATE employment_contracts SET 
		employee_id = ?, employer_id = ?, position = ?, salary = ?, contract_type = ?, start_date = ?, end_date = ?, benefits = ?, contract_terms = ?, active_status = ?
		WHERE contract_id = ?;`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(contract.EmployeeID, contract.EmployerID, contract.Position, contract.Salary, contract.ContractType, contract.StartDate, contract.EndDate, contract.Benefits, contract.ContractTerms, contract.ActiveStatus, contract.ContractID)
	return err
}

// AddTransaction adds a new transaction to the database
func (dm *DatabaseManager) AddTransaction(transaction *Transaction) error {
	stmt, err := dm.db.Prepare(`INSERT INTO transactions (
		transaction_id, contract_id, timestamp, amount, transaction_type, status
	) VALUES (?, ?, ?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(transaction.TransactionID, transaction.ContractID, transaction.Timestamp, transaction.Amount, transaction.TransactionType, transaction.Status)
	return err
}

// GetTransaction retrieves a transaction from the database by transaction ID
func (dm *DatabaseManager) GetTransaction(transactionID string) (*Transaction, error) {
	stmt, err := dm.db.Prepare(`SELECT transaction_id, contract_id, timestamp, amount, transaction_type, status FROM transactions WHERE transaction_id = ?;`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	transaction := &Transaction{}
	err = stmt.QueryRow(transactionID).Scan(&transaction.TransactionID, &transaction.ContractID, &transaction.Timestamp, &transaction.Amount, &transaction.TransactionType, &transaction.Status)
	if err != nil {
		return nil, err
	}

	return transaction, nil
}

// AddSmartContract adds a new smart contract to the database
func (dm *DatabaseManager) AddSmartContract(smartContract *SmartContract) error {
	stmt, err := dm.db.Prepare(`INSERT INTO smart_contracts (
		contract_id, token_id, issuer_id, code, creation_date
	) VALUES (?, ?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(smartContract.ContractID, smartContract.TokenID, smartContract.IssuerID, smartContract.Code, smartContract.CreationDate)
	return err
}

// GetSmartContract retrieves a smart contract from the database by contract ID
func (dm *DatabaseManager) GetSmartContract(contractID string) (*SmartContract, error) {
	stmt, err := dm.db.Prepare(`SELECT contract_id, token_id, issuer_id, code, creation_date FROM smart_contracts WHERE contract_id = ?;`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	smartContract := &SmartContract{}
	err = stmt.QueryRow(contractID).Scan(&smartContract.ContractID, &smartContract.TokenID, &smartContract.IssuerID, &smartContract.Code, &smartContract.CreationDate)
	if err != nil {
		return nil, err
	}

	return smartContract, nil
}

// UpdateSmartContract updates an existing smart contract in the database
func (dm *DatabaseManager) UpdateSmartContract(smartContract *SmartContract) error {
	stmt, err := dm.db.Prepare(`UPDATE smart_contracts SET 
		token_id = ?, issuer_id = ?, code = ?, creation_date = ?
		WHERE contract_id = ?;`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(smartContract.TokenID, smartContract.IssuerID, smartContract.Code, smartContract.CreationDate, smartContract.ContractID)
	return err
}

// Close closes the database connection
func (dm *DatabaseManager) Close() error {
	return dm.db.Close()
}

// EmploymentContract represents an employment contract in the database
type EmploymentContract struct {
	ContractID   string
	EmployeeID   string
	EmployerID   string
	Position     string
	Salary       float64
	ContractType string
	StartDate    string
	EndDate      string
	Benefits     string
	ContractTerms string
	ActiveStatus bool
}

// Transaction represents a transaction in the database
type Transaction struct {
	TransactionID   string
	ContractID      string
	Timestamp       string
	Amount          float64
	TransactionType string
	Status          string
}

// SmartContract represents a smart contract in the database
type SmartContract struct {
	ContractID   string
	TokenID      string
	IssuerID     string
	Code         string
	CreationDate string
}
