package legal_documentation

import (
	"testing"
	"time"
)

// Test data
var testContract = &SmartLegalContract{
	ID:           "12345",
	Jurisdiction: "UK",
	Terms:        "Sample contract terms",
	Parties:      []string{"PartyA", "PartyB"},
}

var updatedTerms = "Updated contract terms to comply with new regulations"

var regulations = []Regulation{
	{
		ID:          "Reg1",
		Requirement: "Sample",
		Description: "Sample regulation requirement",
	},
}

// Mock ComplianceClient
type MockComplianceClient struct{}

func (m *MockComplianceClient) FetchRegulations(jurisdiction string) ([]Regulation, error) {
	return regulations, nil
}

func (m *MockComplianceClient) LogComplianceEvent(contractID, event string) error {
	// Mock implementation of logging compliance event
	return nil
}

// Tests

func TestCreateSmartLegalContract(t *testing.T) {
	client := &MockComplianceClient{}
	service := NewSmartLegalContractService(client)

	err := service.CreateSmartLegalContract(testContract)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !testContract.Compliant {
		t.Fatalf("Expected contract to be compliant")
	}
}

func TestUpdateSmartContract(t *testing.T) {
	client := &MockComplianceClient{}
	service := NewSmartLegalContractService(client)

	err := service.UpdateSmartContract(testContract, updatedTerms)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !testContract.Compliant {
		t.Fatalf("Expected contract to be compliant")
	}
}

func TestSignContract(t *testing.T) {
	client := &MockComplianceClient{}
	service := NewSmartLegalContractService(client)

	privateKey := "private-key"
	err := service.SignContract(testContract, privateKey)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if testContract.SignatureHash == "" {
		t.Fatalf("Expected signature hash to be set")
	}
}

func TestValidateSignature(t *testing.T) {
	client := &MockComplianceClient{}
	service := NewSmartLegalContractService(client)

	privateKey := "private-key"
	publicKey := "public-key"
	err := service.SignContract(testContract, privateKey)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	valid, err := service.ValidateSignature(testContract, publicKey)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !valid {
		t.Fatalf("Expected signature to be valid")
	}
}

func TestAutomatedComplianceCheck(t *testing.T) {
	client := &MockComplianceClient{}
	service := NewSmartLegalContractService(client)

	contracts := []*SmartLegalContract{testContract}
	results, err := service.AutomatedComplianceCheck(contracts)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	for _, result := range results {
		if !result.IsCompliant {
			t.Fatalf("Expected all contracts to be compliant")
		}
	}
}

func TestPeriodicComplianceCheck(t *testing.T) {
	client := &MockComplianceClient{}
	service := NewSmartLegalContractService(client)

	contracts := []*SmartLegalContract{testContract}

	// Mock ticker channel for testing
	ticker := time.NewTicker(2 * time.Second)
	done := make(chan bool)

	go func() {
		time.Sleep(5 * time.Second)
		ticker.Stop()
		done <- true
	}()

	go service.PeriodicComplianceCheck(contracts, ticker)

	<-done
}
