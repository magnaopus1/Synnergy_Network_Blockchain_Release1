package examples

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
)

// SmartContract represents a simple smart contract structure.
type SmartContract struct {
	Code      string `json:"code"`
	Signature string `json:"signature"`
}

// CompileContract compiles the smart contract code into a machine-readable format.
func CompileContract(code string) (string, error) {
	// Placeholder for actual smart contract compilation logic
	// In a real implementation, this would compile the code into bytecode
	return base64.StdEncoding.EncodeToString([]byte(code)), nil
}

// SignContract signs the compiled smart contract using the provided private key.
func SignContract(contract *SmartContract, privKey *ecdsa.PrivateKey) error {
	hash := sha256.Sum256([]byte(contract.Code))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return err
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	contract.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

// VerifySignature verifies the signature of the smart contract using the provided public key.
func VerifySignature(contract *SmartContract, pubKey *ecdsa.PublicKey) bool {
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

// NewSmartContract creates a new smart contract with the given code.
func NewSmartContract(code string) (*SmartContract, error) {
	compiledCode, err := CompileContract(code)
	if err != nil {
		return nil, err
	}
	return &SmartContract{
		Code: compiledCode,
	}, nil
}

// Example usage
func main() {
	// Example smart contract code (Solidity or other supported languages)
	smartContractCode := `
		pragma solidity ^0.8.0;

		contract ExampleContract {
			uint256 public value;

			function setValue(uint256 newValue) public {
				value = newValue;
			}
		}
	`

	// Generate a new smart contract
	contract, err := NewSmartContract(smartContractCode)
	if err != nil {
		log.Fatalf("Error creating smart contract: %v", err)
	}

	// Generate a new key pair for signing
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		log.Fatalf("Error generating key pair: %v", err)
	}

	// Sign the contract
	err = SignContract(contract, privKey)
	if err != nil {
		log.Fatalf("Error signing contract: %v", err)
	}

	// Verify the contract signature
	valid := VerifySignature(contract, pubKey)
	if valid {
		fmt.Println("Signature verification succeeded.")
	} else {
		fmt.Println("Signature verification failed.")
	}

	// Print the contract details
	contractJSON, _ := json.MarshalIndent(contract, "", "  ")
	fmt.Println("Smart Contract:")
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
