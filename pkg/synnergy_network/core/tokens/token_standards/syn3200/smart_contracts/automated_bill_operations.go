package smart_contracts

import (
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"golang.org/x/crypto/scrypt"
)

type AutomatedBillOperation struct {
	OperationID   string    `json:"operation_id"`
	BillID        string    `json:"bill_id"`
	Schedule      time.Time `json:"schedule"`
	Executed      bool      `json:"executed"`
	ExecutionDate time.Time `json:"execution_date"`
	Metadata      string    `json:"metadata"`
}

type AutomatedBillOperationsDB struct {
	DB *leveldb.DB
}

func NewAutomatedBillOperationsDB(dbPath string) (*AutomatedBillOperationsDB, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &AutomatedBillOperationsDB{DB: db}, nil
}

func (abodb *AutomatedBillOperationsDB) CloseDB() error {
	return abodb.DB.Close()
}

func (abodb *AutomatedBillOperationsDB) AddAutomatedBillOperation(operation AutomatedBillOperation) error {
	if err := abodb.ValidateAutomatedBillOperation(operation); err != nil {
		return err
	}
	data, err := json.Marshal(operation)
	if err != nil {
		return err
	}
	return abodb.DB.Put([]byte("automated_bill_operation_"+operation.OperationID), data, nil)
}

func (abodb *AutomatedBillOperationsDB) GetAutomatedBillOperation(operationID string) (*AutomatedBillOperation, error) {
	data, err := abodb.DB.Get([]byte("automated_bill_operation_"+operationID), nil)
	if err != nil {
		return nil, err
	}
	var operation AutomatedBillOperation
	if err := json.Unmarshal(data, &operation); err != nil {
		return nil, err
	}
	return &operation, nil
}

func (abodb *AutomatedBillOperationsDB) GetAllAutomatedBillOperations() ([]AutomatedBillOperation, error) {
	var operations []AutomatedBillOperation
	iter := abodb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var operation AutomatedBillOperation
		if err := json.Unmarshal(iter.Value(), &operation); err != nil {
			return nil, err
		}
		operations = append(operations, operation)
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return operations, nil
}

func (abodb *AutomatedBillOperationsDB) ValidateAutomatedBillOperation(operation AutomatedBillOperation) error {
	if operation.OperationID == "" {
		return errors.New("operation ID must be provided")
	}
	if operation.BillID == "" {
		return errors.New("bill ID must be provided")
	}
	if operation.Schedule.IsZero() {
		return errors.New("schedule date must be provided")
	}
	return nil
}

func (abodb *AutomatedBillOperationsDB) UpdateAutomatedBillOperation(operation AutomatedBillOperation) error {
	if _, err := abodb.GetAutomatedBillOperation(operation.OperationID); err != nil {
		return err
	}
	if err := abodb.ValidateAutomatedBillOperation(operation); err != nil {
		return err
	}
	data, err := json.Marshal(operation)
	if err != nil {
		return err
	}
	return abodb.DB.Put([]byte("automated_bill_operation_"+operation.OperationID), data, nil
}

func (abodb *AutomatedBillOperationsDB) DeleteAutomatedBillOperation(operationID string) error {
	return abodb.DB.Delete([]byte("automated_bill_operation_"+operationID), nil)
}

func (abodb *AutomatedBillOperationsDB) ExecuteDueOperations() error {
	operations, err := abodb.GetAllAutomatedBillOperations()
	if err != nil {
		return err
	}
	now := time.Now()
	for _, operation := range operations {
		if !operation.Executed && operation.Schedule.Before(now) {
			log.Printf("Executing operation ID: %s for Bill ID: %s\n", operation.OperationID, operation.BillID)
			// Execute the bill operation logic here

			// Mark the operation as executed
			operation.Executed = true
			operation.ExecutionDate = time.Now()
			if err := abodb.UpdateAutomatedBillOperation(operation); err != nil {
				return err
			}
		}
	}
	return nil
}

func hashData(data string) (string, error) {
	salt := []byte("somesalt") // Ensure to use a proper salt generation mechanism
	dk, err := scrypt.Key([]byte(data), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return string(dk), nil
}
