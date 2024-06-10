package examples

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
)

// RicardianContract represents a Ricardian contract with both human-readable and machine-readable components.
type RicardianContract struct {
	HumanReadable string `json:"human_readable"`
	MachineCode   string `json:"machine_code"`
	Signature     string `json:"signature"`
}

// GenerateKeyPair generates a new ECDSA private and public key pair.
func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

// SignContract signs the Ricardian contract using the provided private key.
func SignContract(contract *RicardianContract, privKey *ecdsa.PrivateKey) error {
	hash := sha256.Sum256([]byte(contract.HumanReadable + contract.MachineCode))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return err
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	contract.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

// VerifySignature verifies the signature of the Ricardian contract.
func VerifySignature(contract *RicardianContract, pubKey *ecdsa.PublicKey) bool {
	hash := sha256.Sum256([]byte(contract.HumanReadable + contract.MachineCode))
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

// NewRicardianContract creates a new Ricardian contract with the given human-readable terms and machine-readable code.
func NewRicardianContract(humanReadable string, machineCode string) *RicardianContract {
	return &RicardianContract{
		HumanReadable: humanReadable,
		MachineCode:   machineCode,
	}
}

// Example usage
func main() {
	// Human-readable legal terms of the contract
	humanReadable := `
		This agreement ("Agreement") is made between the Buyer and Seller.
		Buyer agrees to purchase, and Seller agrees to sell, the Product under the terms and conditions set forth herein.
	`

	// Machine-readable smart contract code (example in Solidity)
	machineCode := `
		pragma solidity ^0.8.0;

		contract PurchaseAgreement {
			address public buyer;
			address public seller;
			string public product;

			constructor(address _buyer, address _seller, string memory _product) {
				buyer = _buyer;
				seller = _seller;
				product = _product;
			}

			function confirmPurchase() public {
				require(msg.sender == buyer, "Only buyer can confirm purchase.");
				// Logic to transfer ownership or funds
			}
		}
	`

	// Generate a new Ricardian contract
	contract := NewRicardianContract(humanReadable, machineCode)

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
