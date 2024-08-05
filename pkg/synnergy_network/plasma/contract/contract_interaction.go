package contract

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
)

// SmartContract represents a smart contract on the blockchain
type SmartContract struct {
    Address      string
    Code         string
    Owner        string
    Balance      int
    State        map[string]string
    mu           sync.Mutex
    Blockchain   *child_chain.Blockchain
    Transactions []child_chain.Transaction
}

// ContractManager manages the deployment and execution of smart contracts
type ContractManager struct {
    Contracts  map[string]*SmartContract
    mu         sync.Mutex
    Blockchain *child_chain.Blockchain
}

// NewContractManager creates a new ContractManager
func NewContractManager(blockchain *child_chain.Blockchain) *ContractManager {
    return &ContractManager{
        Contracts:  make(map[string]*SmartContract),
        Blockchain: blockchain,
    }
}

// DeployContract deploys a new smart contract to the blockchain
func (cm *ContractManager) DeployContract(code, owner string, initialBalance int) (*SmartContract, error) {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    address := generateContractAddress(code, owner)
    contract := &SmartContract{
        Address:    address,
        Code:       code,
        Owner:      owner,
        Balance:    initialBalance,
        State:      make(map[string]string),
        Blockchain: cm.Blockchain,
    }

    cm.Contracts[address] = contract
    return contract, nil
}

// generateContractAddress generates a unique address for the smart contract
func generateContractAddress(code, owner string) string {
    record := fmt.Sprintf("%s%s%d", code, owner, time.Now().UnixNano())
    hash := sha256.New()
    hash.Write([]byte(record))
    return hex.EncodeToString(hash.Sum(nil))
}

// ExecuteContract executes a smart contract with the given function and arguments
func (sc *SmartContract) ExecuteContract(function string, args []string) (string, error) {
    sc.mu.Lock()
    defer sc.mu.Unlock()

    switch function {
    case "set":
        if len(args) < 2 {
            return "", errors.New("not enough arguments for set function")
        }
        sc.State[args[0]] = args[1]
        return fmt.Sprintf("State updated: %s = %s", args[0], args[1]), nil
    case "get":
        if len(args) < 1 {
            return "", errors.New("not enough arguments for get function")
        }
        value, exists := sc.State[args[0]]
        if !exists {
            return "", errors.New("key not found")
        }
        return value, nil
    default:
        return "", errors.New("unknown function")
    }
}

// getContractState retrieves the state of the smart contract
func (sc *SmartContract) getContractState() map[string]string {
    sc.mu.Lock()
    defer sc.mu.Unlock()

    return sc.State
}

// TransferFunds transfers funds to another contract or address
func (sc *SmartContract) TransferFunds(to string, amount int) error {
    sc.mu.Lock()
    defer sc.mu.Unlock()

    if sc.Balance < amount {
        return errors.New("insufficient funds")
    }

    recipient, exists := sc.Blockchain.GetContract(to)
    if !exists {
        return errors.New("recipient not found")
    }

    sc.Balance -= amount
    recipient.Balance += amount
    return nil
}

// GetContract retrieves a contract by address
func (cm *ContractManager) GetContract(address string) (*SmartContract, bool) {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    contract, exists := cm.Contracts[address]
    return contract, exists
}

// validateContractCode validates the contract code
func validateContractCode(code string) error {
    if len(code) == 0 {
        return errors.New("contract code cannot be empty")
    }
    // Additional validation logic can be added here
    return nil
}

// signContractTransaction signs a transaction using the owner's private key
func signContractTransaction(tx child_chain.Transaction, privateKey string) (string, error) {
    record := tx.Hash + privateKey
    hash := sha256.New()
    hash.Write([]byte(record))
    return hex.EncodeToString(hash.Sum(nil)), nil
}

// verifyContractTransactionSignature verifies the transaction signature using the owner's public key
func verifyContractTransactionSignature(tx child_chain.Transaction, signature, publicKey string) bool {
    record := tx.Hash + publicKey
    hash := sha256.New()
    hash.Write([]byte(record))
    return hex.EncodeToString(hash.Sum(nil)) == signature
}

// AddTransaction adds a transaction to the smart contract
func (sc *SmartContract) AddTransaction(tx child_chain.Transaction) {
    sc.mu.Lock()
    defer sc.mu.Unlock()

    sc.Transactions = append(sc.Transactions, tx)
}

// GetTransactions retrieves all transactions of the smart contract
func (sc *SmartContract) GetTransactions() []child_chain.Transaction {
    sc.mu.Lock()
    defer sc.mu.Unlock()

    return sc.Transactions
}

// InteractWithContract allows external interaction with a smart contract
func (cm *ContractManager) InteractWithContract(contractAddress, function string, args []string) (string, error) {
    contract, exists := cm.GetContract(contractAddress)
    if !exists {
        return "", errors.New("contract not found")
    }
    return contract.ExecuteContract(function, args)
}

// DestroyContract destroys a smart contract
func (cm *ContractManager) DestroyContract(address string) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    _, exists := cm.Contracts[address]
    if !exists {
        return errors.New("contract not found")
    }

    delete(cm.Contracts, address)
    return nil
}

// BackupContractState creates a backup of the contract's state
func (sc *SmartContract) BackupContractState() map[string]string {
    sc.mu.Lock()
    defer sc.mu.Unlock()

    backup := make(map[string]string)
    for key, value := range sc.State {
        backup[key] = value
    }
    return backup
}

// RestoreContractState restores the contract's state from a backup
func (sc *SmartContract) RestoreContractState(backup map[string]string) {
    sc.mu.Lock()
    defer sc.mu.Unlock()

    for key, value := range backup {
        sc.State[key] = value
    }
}

// UpdateContractCode updates the code of the smart contract
func (cm *ContractManager) UpdateContractCode(address, newCode string) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    contract, exists := cm.Contracts[address]
    if !exists {
        return errors.New("contract not found")
    }

    contract.Code = newCode
    return nil
}

// SetContractOwner sets a new owner for the smart contract
func (cm *ContractManager) SetContractOwner(address, newOwner string) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    contract, exists := cm.Contracts[address]
    if !exists {
        return errors.New("contract not found")
    }

    contract.Owner = newOwner
    return nil
}
