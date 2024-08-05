package smart_contracts

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "time"

    "github.com/synnergy_network/core/ledger"
    "github.com/synnergy_network/core/tokens"
    "github.com/synnergy_network/utils"
    "golang.org/x/crypto/argon2"
)

type SmartContract struct {
    ID            string
    Owner         string
    ContractType  string
    CreationDate  time.Time
    LastUpdated   time.Time
    Terms         map[string]string
    Status        string
    Parties       []string
    Signatures    map[string]string
    TransactionID string
}

type ContractManager struct {
    Contracts map[string]SmartContract
    Ledger    *ledger.Ledger
}

func NewContractManager(ledger *ledger.Ledger) *ContractManager {
    return &ContractManager{
        Contracts: make(map[string]SmartContract),
        Ledger:    ledger,
    }
}

func (cm *ContractManager) CreateContract(owner, contractType string, terms map[string]string, parties []string) (*SmartContract, error) {
    contractID := generateContractID(owner, contractType)
    creationDate := time.Now()

    contract := SmartContract{
        ID:            contractID,
        Owner:         owner,
        ContractType:  contractType,
        CreationDate:  creationDate,
        LastUpdated:   creationDate,
        Terms:         terms,
        Status:        "Active",
        Parties:       parties,
        Signatures:    make(map[string]string),
        TransactionID: "",
    }

    cm.Contracts[contractID] = contract

    // Log creation in the ledger
    err := cm.Ledger.RecordTransaction(ledger.Transaction{
        ID:        contractID,
        Timestamp: creationDate,
        Data:      fmt.Sprintf("Contract created: %s", contractID),
    })

    if err != nil {
        return nil, err
    }

    return &contract, nil
}

func (cm *ContractManager) UpdateContract(contractID string, newTerms map[string]string) error {
    contract, exists := cm.Contracts[contractID]
    if !exists {
        return fmt.Errorf("contract not found")
    }

    contract.Terms = newTerms
    contract.LastUpdated = time.Now()
    cm.Contracts[contractID] = contract

    // Log update in the ledger
    err := cm.Ledger.RecordTransaction(ledger.Transaction{
        ID:        contractID,
        Timestamp: contract.LastUpdated,
        Data:      fmt.Sprintf("Contract updated: %s", contractID),
    })

    if err != nil {
        return err
    }

    return nil
}

func (cm *ContractManager) SignContract(contractID, party, signature string) error {
    contract, exists := cm.Contracts[contractID]
    if !exists {
        return fmt.Errorf("contract not found")
    }

    contract.Signatures[party] = signature
    contract.LastUpdated = time.Now()
    cm.Contracts[contractID] = contract

    // Log signature in the ledger
    err := cm.Ledger.RecordTransaction(ledger.Transaction{
        ID:        contractID,
        Timestamp: contract.LastUpdated,
        Data:      fmt.Sprintf("Contract signed by %s: %s", party, contractID),
    })

    if err != nil {
        return err
    }

    return nil
}

func (cm *ContractManager) ExecuteContract(contractID string) error {
    contract, exists := cm.Contracts[contractID]
    if !exists {
        return fmt.Errorf("contract not found")
    }

    contract.Status = "Executed"
    contract.LastUpdated = time.Now()
    cm.Contracts[contractID] = contract

    // Log execution in the ledger
    err := cm.Ledger.RecordTransaction(ledger.Transaction{
        ID:        contractID,
        Timestamp: contract.LastUpdated,
        Data:      fmt.Sprintf("Contract executed: %s", contractID),
    })

    if err != nil {
        return err
    }

    return nil
}

func (cm *ContractManager) TerminateContract(contractID string) error {
    contract, exists := cm.Contracts[contractID]
    if !exists {
        return fmt.Errorf("contract not found")
    }

    contract.Status = "Terminated"
    contract.LastUpdated = time.Now()
    cm.Contracts[contractID] = contract

    // Log termination in the ledger
    err := cm.Ledger.RecordTransaction(ledger.Transaction{
        ID:        contractID,
        Timestamp: contract.LastUpdated,
        Data:      fmt.Sprintf("Contract terminated: %s", contractID),
    })

    if err != nil {
        return err
    }

    return nil
}

func generateContractID(owner, contractType string) string {
    hash := sha256.New()
    hash.Write([]byte(owner + contractType + time.Now().String()))
    return hex.EncodeToString(hash.Sum(nil))
}

func hashPassword(password, salt string) string {
    return hex.EncodeToString(argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32))
}

func verifyPassword(hash, password, salt string) bool {
    return hash == hashPassword(password, salt)
}

func encryptData(data, key string) (string, error) {
    return utils.EncryptAES(data, key)
}

func decryptData(data, key string) (string, error) {
    return utils.DecryptAES(data, key)
}
