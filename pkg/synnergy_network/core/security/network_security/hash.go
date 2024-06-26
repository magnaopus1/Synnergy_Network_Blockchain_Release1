package security

import (
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"log"
)

const (
	Salt       = "unique-salt-string"
	KeyLength  = 32
	ArgonTime  = 1
	ArgonMemory = 64 * 1024
	ArgonThreads = 4
	ScryptN    = 16384
	ScryptR    = 8
	ScryptP    = 1
)

// GenerateSHA256Hash generates a SHA-256 hash of the given data
func GenerateSHA256Hash(data []byte) string {
	hasher := sha256.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}

// GenerateScryptHash generates a Scrypt hash of the given data
func GenerateScryptHash(password []byte) ([]byte, error) {
	salt := []byte(Salt)
	hash, err := scrypt.Key(password, salt, ScryptN, ScryptR, ScryptP, KeyLength)
	if err != nil {
		log.Printf("Error generating Scrypt hash: %v", err)
		return nil, err
	}
	return hash, nil
}

// GenerateArgon2Hash generates an Argon2 hash of the given data
func GenerateArgon2Hash(password []byte) []byte {
	salt := []byte(Salt)
	return argon2.IDKey(password, salt, ArgonTime, ArgonMemory, ArgonThreads, KeyLength)
}

// Example usage
func main() {
	data := []byte("Hello, blockchain world!")
	sha256Hash := GenerateSHA256Hash(data)
	scryptHash, err := GenerateScryptHash(data)
	if err != nil {
		log.Fatal("Failed to generate Scrypt hash: ", err)
	}
	argon2Hash := GenerateArgon2Hash(data)

	log.Printf("SHA-256 Hash: %s", sha256Hash)
	log.Printf("Scrypt Hash: %x", scryptHash)
	log.Printf("Argon2 Hash: %x", argon2Hash)
}
