package contracts

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/smart_contracts"
)

// SmartContractIntegration manages the integration of smart contracts within the SYN131 token standard.
type SmartContractIntegration struct {
	Ledger         *ledger.LedgerManager
	Security       *security.SecurityManager
	ContractStore  map[string]*smart_contracts.SmartContract
}

// NewSmartContractIntegration initializes a new SmartContractIntegration manager.
func NewSmartContractIntegration(ledger *ledger.LedgerManager, security *security.SecurityManager) *SmartContractIntegration {
	return &SmartContractIntegration{
		Ledger:        ledger,
		Security:      security,
		ContractStore: make(map[string]*smart_contracts.SmartContract),
	}
}

// DeploySmartContract deploys a new smart contract for an asset.
func (sci *SmartContractIntegration) DeploySmartContract(assetID, contractCode string, parameters map[string]interface{}) (*smart_contracts.SmartContract, error) {
	// Encrypt the contract code before deployment for security
	encryptedCode, err := sci.Security.Encrypt(contractCode)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt contract code: %v", err)
	}

	sc := smart_contracts.NewSmartContract(encryptedCode, parameters)
	if err := sc.Deploy(); err != nil {
		return nil, err
	}

	// Store the deployed smart contract
	sci.ContractStore[assetID] = sc

	// Record the smart contract deployment in the ledger
	if err := sci.Ledger.RecordSmartContractDeployment(assetID, sc.Address, time.Now()); err != nil {
		return nil, err
	}

	return sc, nil
}

// ExecuteSmartContract executes a smart contract for an asset.
func (sci *SmartContractIntegration) ExecuteSmartContract(assetID string, function string, args map[string]interface{}) (map[string]interface{}, error) {
	sc, exists := sci.ContractStore[assetID]
	if !exists {
		return nil, fmt.Errorf("smart contract for asset ID %s not found", assetID)
	}

	// Decrypt the contract code before execution
	decryptedCode, err := sci.Security.Decrypt(sc.Code)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt contract code: %v", err)
	}

	sc.Code = decryptedCode
	result, err := sc.Execute(function, args)
	if err != nil {
		return nil, err
	}

	// Record the execution of the smart contract in the ledger
	if err := sci.Ledger.RecordSmartContractExecution(assetID, function, args, result, time.Now()); err != nil {
		return nil, err
	}

	return result, nil
}

// UpdateSmartContract updates the code or parameters of a deployed smart contract.
func (sci *SmartContractIntegration) UpdateSmartContract(assetID, newContractCode string, newParameters map[string]interface{}) error {
	sc, exists := sci.ContractStore[assetID]
	if !exists {
		return fmt.Errorf("smart contract for asset ID %s not found", assetID)
	}

	// Encrypt the new contract code before updating
	encryptedCode, err := sci.Security.Encrypt(newContractCode)
	if err != nil {
		return fmt.Errorf("failed to encrypt new contract code: %v", err)
	}

	sc.Code = encryptedCode
	sc.Parameters = newParameters

	// Record the update of the smart contract in the ledger
	if err := sci.Ledger.RecordSmartContractUpdate(assetID, sc.Address, newContractCode, newParameters, time.Now()); err != nil {
		return err
	}

	return nil
}

// TerminateSmartContract terminates an active smart contract.
func (sci *SmartContractIntegration) TerminateSmartContract(assetID string, authorized bool) error {
	if !authorized {
		return errors.New("unauthorized termination")
	}

	sc, exists := sci.ContractStore[assetID]
	if !exists {
		return fmt.Errorf("smart contract for asset ID %s not found", assetID)
	}

	if err := sc.Terminate(); err != nil {
		return err
	}

	// Record the termination of the smart contract in the ledger
	if err := sci.Ledger.RecordSmartContractTermination(assetID, sc.Address, time.Now()); err != nil {
		return err
	}

	// Remove the smart contract from the store
	delete(sci.ContractStore, assetID)

	return nil
}
