package management

import (
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn900/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn900/smart_contracts"
)

// SmartContractManager manages the deployment, interaction, and management of smart contracts for SYN900 tokens
type SmartContractManager struct {
	ledger         *assets.Ledger
	smartContracts map[string]*smart_contracts.SmartContract
}

// NewSmartContractManager initializes a new SmartContractManager
func NewSmartContractManager(ledger *assets.Ledger) *SmartContractManager {
	return &SmartContractManager{
		ledger:         ledger,
		smartContracts: make(map[string]*smart_contracts.SmartContract),
	}
}

// DeploySmartContract deploys a new smart contract
func (scm *SmartContractManager) DeploySmartContract(auth *bind.TransactOpts, backend bind.ContractBackend) (string, error) {
	address, tx, instance, err := smart_contracts.DeploySmartContract(auth, backend)
	if err != nil {
		return "", err
	}

	sc := &smart_contracts.SmartContract{
		Address:  address.Hex(),
		Instance: instance,
		TxHash:   tx.Hash().Hex(),
		Deployed: time.Now(),
	}

	scm.smartContracts[address.Hex()] = sc

	err = scm.ledger.StoreSmartContract(sc)
	if err != nil {
		return "", err
	}

	return address.Hex(), nil
}

// GetSmartContract retrieves a smart contract by its address
func (scm *SmartContractManager) GetSmartContract(address string) (*smart_contracts.SmartContract, error) {
	sc, exists := scm.smartContracts[address]
	if !exists {
		return nil, errors.New("smart contract not found")
	}
	return sc, nil
}

// ExecuteSmartContractFunction executes a function on a deployed smart contract
func (scm *SmartContractManager) ExecuteSmartContractFunction(address string, functionName string, args ...interface{}) (interface{}, error) {
	sc, err := scm.GetSmartContract(address)
	if err != nil {
		return nil, err
	}

	result, err := sc.Instance.ExecuteFunction(functionName, args...)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// UpdateSmartContract updates an existing smart contract
func (scm *SmartContractManager) UpdateSmartContract(address string, newDetails *smart_contracts.SmartContract) error {
	sc, err := scm.GetSmartContract(address)
	if err != nil {
		return err
	}

	sc.Details = newDetails.Details
	sc.Updated = time.Now()

	err = scm.ledger.StoreSmartContract(sc)
	if err != nil {
		return err
	}

	return nil
}

// DeleteSmartContract deletes an existing smart contract from the manager
func (scm *SmartContractManager) DeleteSmartContract(address string) error {
	_, err := scm.GetSmartContract(address)
	if err != nil {
		return err
	}

	delete(scm.smartContracts, address)

	err = scm.ledger.DeleteSmartContract(address)
	if err != nil {
		return err
	}

	return nil
}

// ListSmartContracts lists all deployed smart contracts
func (scm *SmartContractManager) ListSmartContracts() ([]*smart_contracts.SmartContract, error) {
	contracts := []*smart_contracts.SmartContract{}
	for _, sc := range scm.smartContracts {
		contracts = append(contracts, sc)
	}
	return contracts, nil
}
