package core


import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// SmartContract represents a generic smart contract
type SmartContract struct {
	ID         string
	Code       string
	Owner      string
	State      map[string]interface{}
	Interfaces []string
}

// NewSmartContract creates a new smart contract
func NewSmartContract(code string, owner string, interfaces []string) *SmartContract {
	id := generateID(code, owner)
	return &SmartContract{
		ID:         id,
		Code:       code,
		Owner:      owner,
		State:      make(map[string]interface{}),
		Interfaces: interfaces,
	}
}

// Execute runs the smart contract with the given function name and arguments
func (sc *SmartContract) Execute(functionName string, args ...interface{}) (interface{}, error) {
	switch functionName {
	case "setState":
		if len(args) != 2 {
			return nil, errors.New("invalid arguments for setState")
		}
		key, ok := args[0].(string)
		if !ok {
			return nil, errors.New("invalid key type")
		}
		sc.State[key] = args[1]
		return nil, nil
	case "getState":
		if len(args) != 1 {
			return nil, errors.New("invalid arguments for getState")
		}
		key, ok := args[0].(string)
		if !ok {
			return nil, errors.New("invalid key type")
		}
		value, exists := sc.State[key]
		if !exists {
			return nil, fmt.Errorf("state key %s not found", key)
		}
		return value, nil
	default:
		return nil, fmt.Errorf("function %s not found in smart contract", functionName)
	}
}

// Deploy deploys the smart contract to the blockchain
func (sc *SmartContract) Deploy() error {
	// Implement blockchain deployment logic here
	// This is a placeholder
	fmt.Printf("Deploying smart contract %s to the blockchain\n", sc.ID)
	return nil
}

// generateID generates a unique ID for the smart contract based on its code and owner
func generateID(code string, owner string) string {
	hash := sha256.Sum256([]byte(code + owner))
	return hex.EncodeToString(hash[:])
}
