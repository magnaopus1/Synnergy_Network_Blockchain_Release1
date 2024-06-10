package hash

import (
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/argon2"
)

// CryptographicHash encapsulates the logic for the cryptographic hash functions used in the blockchain.
type CryptographicHash struct {
	// Consider configuring additional parameters if needed
}

// NewCryptographicHash creates a new instance of the cryptographic hash utilities.
func NewCryptographicHash() *CryptographicHash {
	return &CryptographicHash{}
}

// GenerateHash generates a cryptographic hash of the given data using SHA-256 and SHA-3 for dual hashing.
func (ch *CryptographicHash) GenerateHash(data []byte) (string, error) {
	if data == nil {
		return "", errors.New("data cannot be nil")
	}

	// First pass SHA-256
	hash256 := sha256.Sum256(data)

	// Second pass SHA-3
	hash3 := sha3.New256()
	_, err := hash3.Write(hash256[:])
	if err != nil {
		return "", err
	}
	finalHash := hash3.Sum(nil)

	return hex.EncodeToString(finalHash), nil
}

// ArgonHash generates a hash using Argon2.
func (ch *CryptographicHash) ArgonHash(password, salt []byte) string {
	hash := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

// Example usage
func main() {
	cryptoHash := NewCryptographicHash()

	// Example data to hash
	data := []byte("Blockchain data block")
	hashedData, err := cryptoHash.GenerateHash(data)
	if err != nil {
		panic("failed to generate hash: " + err.Error())
	}
	println("Dual Hashed Data: ", hashedData)

	// Example of Argon2 usage
	password := []byte("strongpassword")
	salt := []byte("unique_salt")
	argHash := cryptoHash.ArgonHash(password, salt)
	println("Argon2 Hash: ", argHash)
}

// This Go code sets up the cryptographic hash functionality crucial for blockchain integrity. It features dual-layer hashing with SHA-256 and SHA-3, along with an example of Argon2 hashing. This setup ensures robust data security within the Synnergy Network, making it suitable for maintaining the immutability and authenticity of blockchain data.
