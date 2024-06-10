package ricardian_contracts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
)

// RicardianContract represents a Ricardian contract containing both human-readable and machine-executable components.
type RicardianContract struct {
	LegalDocument string            `json:"legal_document"`
	Code          string            `json:"code"`
	Params        map[string]string `json:"params"`
	Signature     string            `json:"signature"`
}

// CompileRicardianContract compiles the Ricardian contract by replacing placeholders with actual parameters.
func CompileRicardianContract(code string, params map[string]string) (string, error) {
	for key, value := range params {
		code = strings.ReplaceAll(code, fmt.Sprintf("{{%s}}", key), value)
	}

	// Placeholder for actual smart contract compilation logic
	// In a real implementation, this would compile the code into bytecode
	return base64.StdEncoding.EncodeToString([]byte(code)), nil
}

// replacePlaceholder is a helper function to replace placeholders in the template code.
func replacePlaceholder(code, placeholder, value string) string {
	return strings.ReplaceAll(code, fmt.Sprintf("{{%s}}", placeholder), value)
}

// SignRicardianContract signs the Ricardian contract using the provided private key.
func SignRicardianContract(contract *RicardianContract, privKey *ecdsa.PrivateKey) error {
	hash := sha256.Sum256([]byte(contract.Code))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return err
	}
	signature := append(r.Bytes(), s.Bytes()...)
	contract.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

// VerifyRicardianContractSignature verifies the signature of the Ricardian contract using the provided public key.
func VerifyRicardianContractSignature(contract *RicardianContract, pubKey *ecdsa.PublicKey) bool {
	hash := sha256.Sum256([]byte(contract.Code))
	signature, err := base64.StdEncoding.DecodeString(contract.Signature)
	if err != nil {
		return false
	}
	r := big.Int{}
	s := big.Int{}
	sigLen := len(signature)
	r.SetBytes(signature[:(sigLen / 2)])
	s.SetBytes(signature[(sigLen / 2):])
	return ecdsa.Verify(pubKey, hash[:], &r, &s)
}

// GenerateKeyPair generates a new ECDSA private and public key pair.
func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

// NewRicardianContract creates a new Ricardian contract with the given legal document, code, and parameters.
func NewRicardianContract(legalDocument, code string, params map[string]string) (*RicardianContract, error) {
	compiledCode, err := CompileRicardianContract(code, params)
	if err != nil {
		return nil, err
	}
	return &RicardianContract{
		LegalDocument: legalDocument,
		Code:          compiledCode,
		Params:        params,
	}, nil
}

// ValidateRicardianContract ensures the contract's code and signature are valid.
func ValidateRicardianContract(contract *RicardianContract, pubKey *ecdsa.PublicKey) error {
	if contract.LegalDocument == "" || contract.Code == "" || contract.Signature == "" {
		return errors.New("contract fields cannot be empty")
	}
	if !VerifyRicardianContractSignature(contract, pubKey) {
		return errors.New("invalid contract signature")
	}
	return nil
}

// Example usage
func main() {
	// Example legal document for the Ricardian contract
	legalDocument := `
	This Agreement is made between {{partyA}} and {{partyB}} on {{date}}.
	The parties agree to the following terms and conditions:
	1. The value shall be {{value}}.
	2. The contract shall be governed by the laws of {{jurisdiction}}.
	`

	// Example smart contract code with placeholders (Solidity or other supported languages)
	smartContractCode := `
	pragma solidity ^0.8.0;

	contract ExampleContract {
		uint256 public value;

		function setValue(uint256 newValue) public {
			value = newValue;
		}
	}
	`

	// Define parameters for the contract
	params := map[string]string{
		"partyA":       "Alice",
		"partyB":       "Bob",
		"date":         "2024-06-01",
		"value":        "1000",
		"jurisdiction": "New York",
	}

	// Generate a new Ricardian contract
	contract, err := NewRicardianContract(legalDocument, smartContractCode, params)
	if err != nil {
		log.Fatalf("Error creating Ricardian contract: %v", err)
	}

	// Generate a new key pair for signing
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		log.Fatalf("Error generating key pair: %v", err)
	}

	// Sign the contract
	err = SignRicardianContract(contract, privKey)
	if err != nil {
		log.Fatalf("Error signing contract: %v", err)
	}

	// Validate the contract
	err = ValidateRicardianContract(contract, pubKey)
	if err != nil {
		log.Fatalf("Contract validation failed: %v", err)
	} else {
		fmt.Println("Contract validation succeeded.")
	}

	// Print the contract details
	contractJSON, _ := json.MarshalIndent(contract, "", "  ")
	fmt.Println("Ricardian Contract:")
	fmt.Println(string(contractJSON))

	// Encode the public key to PEM format for distribution
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Fatalf("Error marshalling public key: %v", err)
	}
	pubKeyPem := base64.StdEncoding.EncodeToString(pubKeyBytes)
	fmt.Println("Public Key PEM:")
	fmt.Println(pubKeyPem)
}
