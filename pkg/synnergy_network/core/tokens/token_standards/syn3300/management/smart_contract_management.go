package management

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/transactions"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/smart_contracts"
)

// SmartContractManager manages the deployment and operation of smart contracts within the SYN3300 standard
type SmartContractManager struct {
	contracts          map[string]smart_contracts.SmartContract
	transactionLedger  *ledger.TransactionService
	encryptionService  *encryption.EncryptionService
}

// NewSmartContractManager creates a new instance of SmartContractManager
func NewSmartContractManager(transactionLedger *ledger.TransactionService, encryptionService *encryption.EncryptionService) *SmartContractManager {
	return &SmartContractManager{
		contracts:         make(map[string]smart_contracts.SmartContract),
		transactionLedger: transactionLedger,
		encryptionService: encryptionService,
	}
}

// DeploySmartContract deploys a new smart contract
func (scm *SmartContractManager) DeploySmartContract(contract smart_contracts.SmartContract) (string, error) {
	contractID := generateContractID()
	contract.ID = contractID
	contract.CreatedAt = time.Now()
	contract.UpdatedAt = time.Now()
	contract.IsActive = true

	encryptedContract, err := scm.encryptionService.EncryptData(contract)
	if err != nil {
		return "", err
	}

	scm.contracts[contractID] = encryptedContract
	return contractID, nil
}

// GetSmartContract retrieves a smart contract by contract ID
func (scm *SmartContractManager) GetSmartContract(contractID string) (*smart_contracts.SmartContract, error) {
	encryptedContract, exists := scm.contracts[contractID]
	if !exists {
		return nil, errors.New("contract not found")
	}

	decryptedContract, err := scm.encryptionService.DecryptData(encryptedContract)
	if err != nil {
		return nil, err
	}

	return &decryptedContract, nil
}

// UpdateSmartContract updates an existing smart contract
func (scm *SmartContractManager) UpdateSmartContract(contractID string, contract smart_contracts.SmartContract) error {
	_, exists := scm.contracts[contractID]
	if !exists {
		return errors.New("contract not found")
	}

	contract.UpdatedAt = time.Now()

	encryptedContract, err := scm.encryptionService.EncryptData(contract)
	if err != nil {
		return err
	}

	scm.contracts[contractID] = encryptedContract
	return nil
}

// DeactivateSmartContract deactivates a smart contract
func (scm *SmartContractManager) DeactivateSmartContract(contractID string) error {
	contract, exists := scm.contracts[contractID]
	if !exists {
		return errors.New("contract not found")
	}

	decryptedContract, err := scm.encryptionService.DecryptData(contract)
	if err != nil {
		return err
	}

	decryptedContract.IsActive = false
	decryptedContract.UpdatedAt = time.Now()

	encryptedContract, err := scm.encryptionService.EncryptData(decryptedContract)
	if err != nil {
		return err
	}

	scm.contracts[contractID] = encryptedContract
	return nil
}

// ExecuteSmartContract executes a smart contract operation
func (scm *SmartContractManager) ExecuteSmartContract(contractID string, operation string, params map[string]interface{}) (interface{}, error) {
	contract, exists := scm.contracts[contractID]
	if !exists {
		return nil, errors.New("contract not found")
	}

	decryptedContract, err := scm.encryptionService.DecryptData(contract)
	if err != nil {
		return nil, err
	}

	if !decryptedContract.IsActive {
		return nil, errors.New("contract is not active")
	}

	result, err := decryptedContract.ExecuteOperation(operation, params)
	if err != nil {
		return nil, err
	}

	// Record the transaction
	transaction := transactions.TransactionRecord{
		ID:            generateTransactionID(),
		ContractID:    contractID,
		Operation:     operation,
		Params:        params,
		Result:        result,
		Timestamp:     time.Now(),
		TransactionStatus: "completed",
	}

	err = scm.transactionLedger.AddTransactionRecord(transaction)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// generateContractID generates a unique contract ID
func generateContractID() string {
	return fmt.Sprintf("contract_%d", time.Now().UnixNano())
}

// generateTransactionID generates a unique transaction ID
func generateTransactionID() string {
	return fmt.Sprintf("tx_%d", time.Now().UnixNano())
}
