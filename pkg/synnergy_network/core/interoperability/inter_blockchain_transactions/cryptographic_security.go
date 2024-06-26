package interblockchaintransactions

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"synthron-blockchain/pkg/crypto"
)

// CryptoService is responsible for providing cryptographic functionalities.
type CryptoService struct{}

// NewCryptoService creates a new instance of CryptoService.
func NewCryptoService() *CryptoService {
	return &CryptoService{}
}

// GenerateKeyPair generates a new ECDSA key pair for signing transactions.
func (cs *CryptoService) GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// SignTransaction signs the transaction data using the given private key.
func (cs *CryptoService) SignTransaction(privateKey *ecdsa.PrivateKey, transactionData []byte) (string, error) {
	hash := sha256.Sum256(transactionData)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %v", err)
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	return hex.EncodeToString(signature), nil
}

// VerifySignature verifies the transaction signature.
func (cs *CryptoService) VerifySignature(publicKey *ecdsa.PublicKey, transactionData []byte, signature string) bool {
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		fmt.Printf("error decoding signature: %v\n", err)
		return false
	}
	r := big.Int{}
	s := big.Int{}
	sigLen := len(sigBytes)
	r.SetBytes(sigBytes[:(sigLen / 2)])
	s.SetBytes(sigBytes[(sigLen / 2):])

	hash := sha256.Sum256(transactionData)
	return ecdsa.Verify(publicKey, hash[:], &r, &s)
}

// Example usage of the CryptoService
func main() {
	cryptoService := NewCryptoService()

	// Generate key pair
	privateKey, err := cryptoService.GenerateKeyPair()
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		return
	}
	publicKey := &privateKey.PublicKey

	// Transaction data
	transactionData := []byte("cross-chain transaction data")

	// Sign transaction
	signature, err := cryptoService.SignTransaction(privateKey, transactionData)
	if err != nil {
		fmt.Println("Error signing transaction:", err)
		return
	}
	fmt.Println("Signature:", signature)

	// Verify signature
	isValid := cryptoService.VerifySignature(publicKey, transactionData, signature)
	if !isValid {
		fmt.Println("Failed to verify signature.")
		return
	}
	fmt.Println("Signature verified successfully!")
}
