package integration

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/assets"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/contracts"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/storage"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/transactions"
)

// CreationTools provides functionalities to create and manage SYN131 smart contracts
type CreationTools struct {
	Storage storage.Storage
}

// NewCreationTools initializes a new CreationTools instance
func NewCreationTools(storage storage.Storage) *CreationTools {
	return &CreationTools{
		Storage: storage,
	}
}

// CreateSmartContract creates a new SYN131 smart contract
func (ct *CreationTools) CreateSmartContract(contract *contracts.Syn131SmartContract, encryptionKey string) error {
	// Encrypt contract terms
	encryptedTerms, err := security.Encrypt(contract.Terms, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt contract terms: %w", err)
	}
	contract.EncryptedTerms = encryptedTerms
	contract.EncryptionKey = ""

	// Validate contract
	if err := ct.validateContract(contract); err != nil {
		return fmt.Errorf("contract validation failed: %w", err)
	}

	// Store contract in storage
	if err := ct.Storage.Save(contract.ID, contract); err != nil {
		return fmt.Errorf("failed to store contract: %w", err)
	}

	return nil
}

// validateContract validates the essential fields of the SYN131 smart contract
func (ct *CreationTools) validateContract(contract *contracts.Syn131SmartContract) error {
	if contract.ID == "" || contract.Owner == "" || contract.IntangibleAssetID == "" {
		return errors.New("missing essential contract fields")
	}

	// Further validations can be added as per business logic
	return nil
}

// UpdateSmartContract updates an existing SYN131 smart contract
func (ct *CreationTools) UpdateSmartContract(contract *contracts.Syn131SmartContract, encryptionKey string) error {
	// Encrypt contract terms
	encryptedTerms, err := security.Encrypt(contract.Terms, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt contract terms: %w", err)
	}
	contract.EncryptedTerms = encryptedTerms
	contract.EncryptionKey = ""

	// Validate contract
	if err := ct.validateContract(contract); err != nil {
		return fmt.Errorf("contract validation failed: %w", err)
	}

	// Update contract in storage
	if err := ct.Storage.Save(contract.ID, contract); err != nil {
		return fmt.Errorf("failed to update contract: %w", err)
	}

	return nil
}

// GetSmartContract retrieves a SYN131 smart contract by its ID
func (ct *CreationTools) GetSmartContract(contractID, decryptionKey string) (*contracts.Syn131SmartContract, error) {
	// Retrieve contract from storage
	data, err := ct.Storage.Load(contractID)
	if err != nil {
		return nil, fmt.Errorf("failed to load contract: %w", err)
	}

	var contract contracts.Syn131SmartContract
	if err := json.Unmarshal(data, &contract); err != nil {
		return nil, fmt.Errorf("failed to unmarshal contract: %w", err)
	}

	// Decrypt contract terms
	decryptedTerms, err := security.Decrypt(contract.EncryptedTerms, decryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt contract terms: %w", err)
	}
	contract.Terms = decryptedTerms

	return &contract, nil
}

// DeleteSmartContract deletes a SYN131 smart contract by its ID
func (ct *CreationTools) DeleteSmartContract(contractID string) error {
	// Delete contract from storage
	if err := ct.Storage.Delete(contractID); err != nil {
		return fmt.Errorf("failed to delete contract: %w", err)
	}
	return nil
}

// ListSmartContracts lists all SYN131 smart contracts
func (ct *CreationTools) ListSmartContracts() ([]contracts.Syn131SmartContract, error) {
	// Retrieve all contracts from storage
	dataList, err := ct.Storage.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list contracts: %w", err)
	}

	var contractsList []contracts.Syn131SmartContract
	for _, data := range dataList {
		var contract contracts.Syn131SmartContract
		if err := json.Unmarshal(data, &contract); err != nil {
			return nil, fmt.Errorf("failed to unmarshal contract: %w", err)
		}
		contractsList = append(contractsList, contract)
	}

	return contractsList, nil
}
