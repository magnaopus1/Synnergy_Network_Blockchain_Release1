package examples

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
)

// SmartContractTemplate represents a template for creating various types of smart contracts.
type SmartContractTemplate struct {
	Code      string            `json:"code"`
	Params    map[string]string `json:"params"`
	Signature string            `json:"signature"`
}

// CompileTemplate compiles the smart contract template into a machine-readable format.
func CompileTemplate(templateCode string, params map[string]string) (string, error) {
	// Replace template placeholders with actual parameters
	for key, value := range params {
		templateCode = replacePlaceholder(templateCode, key, value)
	}

	// Placeholder for actual smart contract compilation logic
	// In a real implementation, this would compile the code into bytecode
	return base64.StdEncoding.EncodeToString([]byte(templateCode)), nil
}

// replacePlaceholder is a helper function to replace placeholders in the template code
func replacePlaceholder(templateCode, placeholder, value string) string {
	return strings.ReplaceAll(templateCode, fmt.Sprintf("{{%s}}", placeholder), value)
}

// SignTemplate signs the compiled smart contract template using the provided private key.
func SignTemplate(template *SmartContractTemplate, privKey *ecdsa.PrivateKey) error {
	hash := sha256.Sum256([]byte(template.Code))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return err
	}
	signature := append(r.Bytes(), s.Bytes()...)
	template.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

// VerifyTemplateSignature verifies the signature of the smart contract template using the provided public key.
func VerifyTemplateSignature(template *SmartContractTemplate, pubKey *ecdsa.PublicKey) bool {
	hash := sha256.Sum256([]byte(template.Code))
	signature, err := base64.StdEncoding.DecodeString(template.Signature)
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

// NewSmartContractTemplate creates a new smart contract template with the given code and parameters.
func NewSmartContractTemplate(code string, params map[string]string) (*SmartContractTemplate, error) {
	compiledCode, err := CompileTemplate(code, params)
	if err != nil {
		return nil, err
	}
	return &SmartContractTemplate{
		Code:   compiledCode,
		Params: params,
	}, nil
}

// Example usage
func main() {
	// Example smart contract template code with placeholders (Solidity or other supported languages)
	smartContractTemplateCode := `
		pragma solidity ^0.8.0;

		contract ExampleContract {
			uint256 public value;

			function setValue(uint256 newValue) public {
				value = newValue;
			}
		}
	`

	// Define parameters for the template
	params := map[string]string{
		"value": "42",
	}

	// Generate a new smart contract template
	template, err := NewSmartContractTemplate(smartContractTemplateCode, params)
	if err != nil {
		log.Fatalf("Error creating smart contract template: %v", err)
	}

	// Generate a new key pair for signing
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		log.Fatalf("Error generating key pair: %v", err)
	}

	// Sign the template
	err = SignTemplate(template, privKey)
	if err != nil {
		log.Fatalf("Error signing template: %v", err)
	}

	// Verify the template signature
	valid := VerifyTemplateSignature(template, pubKey)
	if valid {
		fmt.Println("Signature verification succeeded.")
	} else {
		fmt.Println("Signature verification failed.")
	}

	// Print the template details
	templateJSON, _ := json.MarshalIndent(template, "", "  ")
	fmt.Println("Smart Contract Template:")
	fmt.Println(string(templateJSON))

	// Encode the public key to PEM format for distribution
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Fatalf("Error marshalling public key: %v", err)
	}
	pubKeyPem := base64.StdEncoding.EncodeToString(pubKeyBytes)
	fmt.Println("Public Key PEM:")
	fmt.Println(pubKeyPem)
}
