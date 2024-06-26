package crosschainoracles

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synthron/synthronchain/contracts"
	"github.com/synthron/synthronchain/crypto"
)

// TriggerManager manages the activation of smart contract triggers based on external data conditions.
type TriggerManager struct {
	oracle OracleClient
}

// NewTriggerManager initializes a new manager with a reference to an OracleClient.
func NewTriggerManager(oracle OracleClient) *TriggerManager {
	return &TriggerManager{
		oracle: oracle,
	}
}

// OracleClient interface abstracts the methods provided by the cross-chain oracle.
type OracleClient interface {
	FetchData(query string) (OracleData, error)
	VerifyData(data OracleData) (bool, error)
}

// OracleData represents the data structure returned by an oracle.
type OracleData struct {
	DataHash string
	Payload  interface{}
}

// TriggerCondition defines the structure for trigger conditions.
type TriggerCondition struct {
	Key   string
	Value interface{}
}

// EvaluateTrigger checks if given conditions are met and triggers a smart contract function if they are.
func (tm *TriggerManager) EvaluateTrigger(contractAddress string, conditions []TriggerCondition) error {
	data, err := tm.oracle.FetchData("https://api.example.com/data")
	if err != nil {
		return err
	}

	valid, err := tm.oracle.VerifyData(data)
	if !valid || err != nil {
		return errors.New("failed to verify oracle data")
	}

	for _, condition := range conditions {
		if data.Payload.(map[string]interface{})[condition.Key] == condition.Value {
			err := tm.invokeSmartContract(contractAddress, data.Payload)
			if err != nil {
				return err
			}
			break
		}
	}

	return nil
}

// invokeSmartContract executes the function on the specified smart contract.
func (tm *TriggerManager) invokeSmartContract(contractAddress string, payload interface{}) error {
	// Simulated smart contract execution
	return contracts.ExecuteContract(contractAddress, payload)
}

// Mock implementation of OracleClient for demonstration
type MockOracleClient struct{}

func (moc *MockOracleClient) FetchData(query string) (OracleData, error) {
	// Simulated fetch
	return OracleData{
		DataHash: hashData("sample data"),
		Payload:  map[string]interface{}{"temperature": 30},
	}, nil
}

func (moc *MockOracleClient) VerifyData(data OracleData) (bool, error) {
	// Simulated verification
	expectedHash := hashData("sample data")
	return expectedHash == data.DataHash, nil
}

func hashData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Example usage
func main() {
	oracle := &MockOracleClient{}
	manager := NewTriggerManager(oracle)
	conditions := []TriggerCondition{
		{Key: "temperature", Value: 30},
	}
	err := manager.EvaluateTrigger("0x12345", conditions)
	if err != nil {
		panic(err)
	}
}
