package consensus

import (
    "fmt"
    "sync"

    "synnergy_network/pkg/synnergy_network/core/blockchain"
    "synnergy_network/pkg/synnergy_network/core/smartcontract"
)

// SmartContractPoH extends the PoH to include smart contract integration.
type SmartContractPoH struct {
    *PoH
    SmartContractEngine *smartcontract.Engine
}

// NewSmartContractPoH initializes PoH with smart contract capabilities.
func NewSmartContractPoH() *SmartContractPoH {
    return &SmartContractPoH{
        PoH: NewPoH(),
        SmartContractEngine: smartcontract.NewEngine(),
    }
}

// ExecuteSmartContract executes the given smart contract on the blockchain.
func (scp *SmartContractPoH) ExecuteSmartContract(contract *smartcontract.Contract, params []interface{}) (interface{}, error) {
    result, err := scp.SmartContractEngine.Execute(contract, params)
    if err != nil {
        return nil, fmt.Errorf("smart contract execution failed: %v", err)
    }
    return result, nil
}

// ValidateSmartContract ensures the smart contract's integrity and compliance with PoH standards.
func (scp *SmartContractPoH) ValidateSmartContract(contract *smartcontract.Contract) error {
    if !scp.SmartContractEngine.Validate(contract) {
        return fmt.Errorf("smart contract validation failed")
    }
    return nil
}

// AppendContractTransaction integrates a smart contract transaction into the PoH blockchain.
func (scp *SmartContractPoH) AppendContractTransaction(tx *blockchain.Transaction) error {
    if err := scp.ValidateTransaction(tx); err != nil {
        return err
    }
    return scp.PoH.AppendTransaction(tx)
}

// ValidateTransaction extends the base PoH transaction validation to include smart contract logic.
func (scp *SmartContractPoH) ValidateTransaction(tx *blockchain.Transaction) error {
    // Basic PoH validation
    if err := scp.PoH.ValidateTransaction(tx); err != nil {
        return err
    }

    // Smart contract specific validation
    if tx.IsSmartContract() {
        if err := scp.ValidateSmartContract(tx.Contract); err != nil {
            return fmt.Errorf("smart contract transaction validation failed: %v", err)
        }
    }

    return nil
}

// DeploySmartContract deploys a new smart contract to the blockchain.
func (scp *SmartContractPoH) DeploySmartContract(contract *smartcontract.Contract) error {
    if err := scp.SmartContractEngine.Deploy(contract); err != nil {
        return fmt.Errorf("failed to deploy smart contract: %v", err)
    }
    return nil
}

// SynchronizeContracts synchronizes smart contracts across nodes in the network.
func (scp *SmartContractPoH) SynchronizeContracts() error {
    var wg sync.WaitGroup
    contracts := scp.SmartContractEngine.GetAllContracts()
    for _, contract := range contracts {
        wg.Add(1)
        go func(c *smartcontract.Contract) {
            defer wg.Done()
            if err := scp.DeploySmartContract(c); err != nil {
                fmt.Println("Error synchronizing contract:", err)
            }
        }(contract)
    }
    wg.Wait()
    return nil
}

