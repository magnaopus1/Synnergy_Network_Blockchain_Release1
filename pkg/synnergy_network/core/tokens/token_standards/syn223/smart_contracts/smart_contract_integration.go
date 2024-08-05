package smart_contracts

import (
	"errors"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn223/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/utils"
)

// SmartContractIntegrationManager handles the integration of smart contracts with the SYN223 token standard.
type SmartContractIntegrationManager struct {
	mu             sync.RWMutex
	ledger         *ledger.Ledger
	allowedContracts map[string]bool
	securityManager  *security.SecurityManager
}

// NewSmartContractIntegrationManager initializes a new SmartContractIntegrationManager instance.
func NewSmartContractIntegrationManager(ledger *ledger.Ledger, securityManager *security.SecurityManager) *SmartContractIntegrationManager {
	return &SmartContractIntegrationManager{
		ledger:           ledger,
		allowedContracts: make(map[string]bool),
		securityManager:  securityManager,
	}
}

// AddAllowedContract adds a contract address to the list of allowed contracts.
func (scim *SmartContractIntegrationManager) AddAllowedContract(contractAddress string) error {
	scim.mu.Lock()
	defer scim.mu.Unlock()

	if scim.allowedContracts[contractAddress] {
		return errors.New("contract already allowed")
	}

	scim.allowedContracts[contractAddress] = true
	return nil
}

// RemoveAllowedContract removes a contract address from the list of allowed contracts.
func (scim *SmartContractIntegrationManager) RemoveAllowedContract(contractAddress string) error {
	scim.mu.Lock()
	defer scim.mu.Unlock()

	if !scim.allowedContracts[contractAddress] {
		return errors.New("contract not found in allowed list")
	}

	delete(scim.allowedContracts, contractAddress)
	return nil
}

// IsAllowedContract checks if a contract address is in the list of allowed contracts.
func (scim *SmartContractIntegrationManager) IsAllowedContract(contractAddress string) bool {
	scim.mu.RLock()
	defer scim.mu.RUnlock()

	return scim.allowedContracts[contractAddress]
}

// ExecuteSmartContractTransaction handles the execution of a smart contract transaction.
func (scim *SmartContractIntegrationManager) ExecuteSmartContractTransaction(from, to string, amount uint64, contractData []byte) error {
	scim.mu.Lock()
	defer scim.mu.Unlock()

	if !scim.IsAllowedContract(to) {
		return errors.New("transaction to unsupported contract address")
	}

	if !scim.securityManager.VerifySignature(contractData) {
		return errors.New("invalid contract data signature")
	}

	if err := scim.ledger.TransferTokens(from, to, amount); err != nil {
		return err
	}

	scim.logTransaction(from, to, amount, contractData)
	return nil
}

// logTransaction logs the details of a smart contract transaction.
func (scim *SmartContractIntegrationManager) logTransaction(from, to string, amount uint64, contractData []byte) {
	// Implement logic to log the transaction details
	// This could involve storing the transaction in a database or ledger
}

// EncryptContractData encrypts contract data using AES-GCM with a passphrase.
func (scim *SmartContractIntegrationManager) EncryptContractData(contractData []byte, passphrase string) (string, error) {
	return utils.EncryptData(string(contractData), passphrase)
}

// DecryptContractData decrypts contract data using AES-GCM with a passphrase.
func (scim *SmartContractIntegrationManager) DecryptContractData(encryptedData, passphrase string) ([]byte, error) {
	decryptedString, err := utils.DecryptData(encryptedData, passphrase)
	if err != nil {
		return nil, err
	}
	return []byte(decryptedString), nil
}

// VerifySmartContract verifies the authenticity and integrity of a smart contract.
func (scim *SmartContractIntegrationManager) VerifySmartContract(contractData []byte, signature []byte) bool {
	return scim.securityManager.VerifySignatureWithData(contractData, signature)
}
