package smart_contract_testing

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/synnergy_network/blockchain"
	"github.com/synnergy_network/encryption"
	"github.com/synnergy_network/smartcontracts"
)

// SmartContractUnitTest represents the structure for a unit test on a smart contract function
type SmartContractUnitTest struct {
	ContractID     string
	FunctionName   string
	Params         map[string]interface{}
	ExpectedOutput interface{}
	ActualOutput   interface{}
	Passed         bool
}

// UnitTestSuite represents the suite for unit testing of smart contracts
type UnitTestSuite struct {
	tests   []SmartContractUnitTest
	network *blockchain.Network
}

// NewUnitTestSuite creates a new instance of UnitTestSuite
func NewUnitTestSuite(network *blockchain.Network) *UnitTestSuite {
	return &UnitTestSuite{
		tests:   []SmartContractUnitTest{},
		network: network,
	}
}

// AddTest adds a new unit test to the suite
func (uts *UnitTestSuite) AddTest(contractID, functionName string, params map[string]interface{}, expectedOutput interface{}) {
	test := SmartContractUnitTest{
		ContractID:     contractID,
		FunctionName:   functionName,
		Params:         params,
		ExpectedOutput: expectedOutput,
	}
	uts.tests = append(uts.tests, test)
}

// RunAllTests executes all unit tests in the suite and logs the results
func (uts *UnitTestSuite) RunAllTests(t *testing.T) {
	for _, test := range uts.tests {
		err := uts.ExecuteTest(test)
		if err != nil {
			t.Errorf("Test failed: %v", err)
		}
	}
}

// ExecuteTest executes a specific test
func (uts *UnitTestSuite) ExecuteTest(test SmartContractUnitTest) error {
	output, err := uts.network.ExecuteContractFunction(test.ContractID, test.FunctionName, test.Params)
	if err != nil {
		test.Passed = false
		test.ActualOutput = err.Error()
	} else {
		test.Passed = (output == test.ExpectedOutput)
		test.ActualOutput = output
	}
	logTestResult(test)
	return err
}

// logTestResult logs the result of a unit test
func logTestResult(test SmartContractUnitTest) {
	if test.Passed {
		log.Printf("Test passed for contract %s, function %s: expected %v, got %v", test.ContractID, test.FunctionName, test.ExpectedOutput, test.ActualOutput)
	} else {
		log.Printf("Test failed for contract %s, function %s: expected %v, got %v", test.ContractID, test.FunctionName, test.ExpectedOutput, test.ActualOutput)
	}
}

// GenerateUniqueID generates a unique identifier for test IDs
func GenerateUniqueID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("Failed to generate unique ID: %v", err)
	}
	return hex.EncodeToString(b)
}

// EncryptData encrypts the provided data using AES encryption
func EncryptData(data string, key []byte) (string, error) {
	encrypted, err := encryption.AESEncrypt([]byte(data), key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encrypted), nil
}

// DecryptData decrypts the provided data using AES encryption
func DecryptData(data string, key []byte) (string, error) {
	encrypted, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}
	decrypted, err := encryption.AESDecrypt(encrypted, key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

