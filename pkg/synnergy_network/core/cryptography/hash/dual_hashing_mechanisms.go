package hash

import (
	"crypto/sha256"
	"golang.org/x/crypto/sha3"
	"encoding/hex"
	"fmt"
)

// DualHashingMechanism provides functionality to perform dual hashing on data.
type DualHashingMechanism struct{}

// NewDualHashingMechanism creates a new instance of DualHashingMechanism.
func NewDualHashingMechanism() *DualHashingMechanism {
	return &DualHashingMechanism{}
}

// DualHash performs a dual hash on the input data using SHA-256 and SHA-3.
// It first hashes the data with SHA-256, then hashes the result with SHA-3.
func (dhm *DualHashingMechanism) DualHash(data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("input data cannot be empty")
	}

	// First layer of hashing using SHA-256
	sha256Hasher := sha256.New()
	if _, err := sha256Hasher.Write(data); err != nil {
		return "", fmt.Errorf("failed to write data to SHA-256 hasher: %v", err)
	}
	firstHash := sha256Hasher.Sum(nil)

	// Second layer of hashing using SHA-3
	sha3Hasher := sha3.New256()
	if _, err := sha3Hasher.Write(firstHash); err != nil {
		return "", fmt.Errorf("failed to write data to SHA-3 hasher: %v", err)
	}
	secondHash := sha3Hasher.Sum(nil)

	return hex.EncodeToString(secondHash), nil
}

// Example usage of DualHashingMechanism
func main() {
	dhm := NewDualHashingMechanism()

	// Example data to hash
	exampleData := []byte("Example data for dual hashing.")
	hashed, err := dhm.DualHash(exampleData)
	if err != nil {
		fmt.Println("Error performing dual hash:", err)
		return
	}

	fmt.Println("Dual hashed data:", hashed)
}

// This implementation sets up a dual hashing mechanism essential for ensuring the security and integrity of blockchain data. It employs SHA-256 and SHA-3 hashing algorithms in sequence to mitigate vulnerabilities and enhance cryptographic security. This dual-layer approach is part of a broader strategy to maintain the reliability and safety of the Synnergy Network.
