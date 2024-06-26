package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcutil/hdkeychain"
)

// HDWallet represents a Hierarchical Deterministic Wallet.
type HDWallet struct {
	MasterKey *hdkeychain.ExtendedKey
}

// NewHDWallet creates a new HD wallet using a seed.
func NewHDWallet(seed []byte) (*HDWallet, error) {
	masterKey, err := hdkeychain.NewMaster(seed, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %v", err)
	}
	return &HDWallet{MasterKey: masterKey}, nil
}

// GenerateChildKey derives a child key from the master key at a specific index.
func (w *HDWallet) GenerateChildKey(index uint32) (*ecdsa.PrivateKey, error) {
	childKey, err := w.MasterKey.Child(index)
	if err != nil {
		return nil, fmt.Errorf("failed to generate child key: %v", err)
	}

	ecPrivKey, err := childKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to convert child key to ECDSA private key: %v", err)
	}

	return ecPrivKey.ToECDSA(), nil
}

// Address generates a public address from an ECDSA private key.
func Address(privateKey *ecdsa.PrivateKey) string {
	pubKey := privateKey.PublicKey
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), pubKey.X, pubKey.Y)
	return hex.EncodeToString(pubKeyBytes)
}

// Example usage
func main() {
	seed := make([]byte, 32) // This should be a securely generated seed
	_, err := rand.Read(seed)
	if err != nil {
		fmt.Println("Error generating seed:", err)
		return
	}

	wallet, err := NewHDWallet(seed)
	if err != nil {
		fmt.Println("Error creating wallet:", err)
		return
	}

	childKey, err := wallet.GenerateChildKey(0) // Generate the first child key
	if err != nil {
		fmt.Println("Error generating child key:", err)
		return
	}

	address := Address(childKey)
	fmt.Println("Generated address:", address)
}

// This implementation of HDWallet provides an effective method to manage keys within the Synnergy Network, enhancing security by allowing users to derive multiple keys from a single seed. It uses well-known libraries and cryptographic standards to ensure the reliability and safety of key generation and management, aligning with the best practices in blockchain technology.
