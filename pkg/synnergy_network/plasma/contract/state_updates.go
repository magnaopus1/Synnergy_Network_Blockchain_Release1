package contract

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
    "golang.org/x/crypto/scrypt"
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
    Version      int
    Events       []Event
}

// Event represents an event emitted by a smart contract
type Event struct {
    Name      string
    Data      map[string]interface{}
    Timestamp time.Time
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
        Version:    1,
        Events:     []Event{},
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

// EmitEvent emits an event from a smart contract
func (sc *SmartContract) EmitEvent(eventName string, data map[string]interface{}) {
    sc.mu.Lock()
    defer sc.mu.Unlock()

    event := Event{
        Name:      eventName,
        Data:      data,
        Timestamp: time.Now(),
    }

    sc.Events = append(sc.Events, event)
}

// GetEvents retrieves all events emitted by the smart contract
func (sc *SmartContract) GetEvents() []Event {
    sc.mu.Lock()
    defer sc.mu.Unlock()

    return sc.Events
}

// CrossContractCall facilitates interaction between two smart contracts
func (cm *ContractManager) CrossContractCall(fromAddress, toAddress, function string, args []string) (string, error) {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    fromContract, fromExists := cm.Contracts[fromAddress]
    toContract, toExists := cm.Contracts[toAddress]

    if !fromExists || !toExists {
        return "", errors.New("one or both contracts not found")
    }

    result, err := toContract.ExecuteContract(function, args)
    if err != nil {
        return "", err
    }

    transaction := child_chain.Transaction{
        From:   fromAddress,
        To:     toAddress,
        Amount: 0,
        Data:   fmt.Sprintf("%s|%v", function, args),
        Hash:   generateTransactionHash(fromAddress, toAddress, function, args),
    }

    fromContract.AddTransaction(transaction)
    toContract.AddTransaction(transaction)

    return result, nil
}

// generateTransactionHash generates a hash for a cross-contract transaction
func generateTransactionHash(fromAddress, toAddress, function string, args []string) string {
    record := fmt.Sprintf("%s%s%s%v%d", fromAddress, toAddress, function, args, time.Now().UnixNano())
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
        sc.EmitEvent("StateChanged", map[string]interface{}{"key": args[0], "value": args[1]})
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
    sc.EmitEvent("FundsTransferred", map[string]interface{}{"to": to, "amount": amount})
    return nil
}

// GetContract retrieves a contract by address
func (cm *ContractManager) GetContract(address string) (*SmartContract, bool) {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    contract, exists := cm.Contracts[address]
    return contract, exists
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
