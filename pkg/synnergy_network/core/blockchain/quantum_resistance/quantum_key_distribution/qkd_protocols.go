package quantum_key_distribution

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"io"
	"net"
)

// Constants for Argon2 and Scrypt
const (
	Argon2Time        = 1
	Argon2Memory      = 64 * 1024
	Argon2Threads     = 4
	Argon2KeyLen      = 32
	ScryptN           = 32768
	ScryptR           = 8
	ScryptP           = 1
	ScryptKeyLen      = 32
	SaltLen           = 16
	HMACKeyLen        = 32
)

// GenerateRandomBytes generates random bytes of specified length
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// GenerateArgon2Key generates a key using the Argon2 algorithm
func GenerateArgon2Key(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
}

// GenerateScryptKey generates a key using the Scrypt algorithm
func GenerateScryptKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, ScryptN, ScryptR, ScryptP, ScryptKeyLen)
}

// GenerateHMAC generates an HMAC for the given data using the provided key
func GenerateHMAC(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMAC verifies the HMAC of the given data using the provided key
func VerifyHMAC(data, key, hmacToCompare []byte) bool {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	expectedHMAC := h.Sum(nil)
	return hmac.Equal(expectedHMAC, hmacToCompare)
}

// QuantumKeyExchangeProtocol represents a quantum key exchange protocol
type QuantumKeyExchangeProtocol struct {
	conn      net.Conn
	localKey  []byte
	remoteKey []byte
}

// NewQuantumKeyExchangeProtocol creates a new QuantumKeyExchangeProtocol
func NewQuantumKeyExchangeProtocol(conn net.Conn, password []byte) (*QuantumKeyExchangeProtocol, error) {
	salt, err := GenerateRandomBytes(SaltLen)
	if err != nil {
		return nil, err
	}

	localKey := GenerateArgon2Key(password, salt)

	return &QuantumKeyExchangeProtocol{
		conn:     conn,
		localKey: localKey,
	}, nil
}

// ExchangeKeys exchanges quantum-generated keys between nodes
func (q *QuantumKeyExchangeProtocol) ExchangeKeys() error {
	// Send local key to the remote node
	_, err := q.conn.Write(q.localKey)
	if err != nil {
		return err
	}

	// Receive remote key from the remote node
	q.remoteKey = make([]byte, Argon2KeyLen)
	_, err = io.ReadFull(q.conn, q.remoteKey)
	if err != nil {
		return err
	}

	return nil
}

// VerifyKeyExchange verifies the integrity of the key exchange
func (q *QuantumKeyExchangeProtocol) VerifyKeyExchange(data []byte) (bool, error) {
	hmac := GenerateHMAC(data, q.remoteKey)
	_, err := q.conn.Write(hmac)
	if err != nil {
		return false, err
	}

	// Receive HMAC from the remote node
	remoteHMAC := make([]byte, sha256.Size)
	_, err = io.ReadFull(q.conn, remoteHMAC)
	if err != nil {
		return false, err
	}

	return VerifyHMAC(data, q.localKey, remoteHMAC), nil
}

// QuantumKeyManager manages quantum keys and their lifecycle
type QuantumKeyManager struct {
	keys map[string][]byte
}

// NewQuantumKeyManager creates a new QuantumKeyManager
func NewQuantumKeyManager() *QuantumKeyManager {
	return &QuantumKeyManager{
		keys: make(map[string][]byte),
	}
}

// AddKey adds a quantum key for a given chain ID
func (qm *QuantumKeyManager) AddKey(chainID string, password []byte) error {
	salt, err := GenerateRandomBytes(SaltLen)
	if err != nil {
		return err
	}

	key := GenerateArgon2Key(password, salt)
	qm.keys[chainID] = key
	return nil
}

// GetKey retrieves the quantum key for a given chain ID
func (qm *QuantumKeyManager) GetKey(chainID string) ([]byte, error) {
	key, exists := qm.keys[chainID]
	if !exists {
		return nil, errors.New("key not found")
	}
	return key, nil
}

// SecureKeyExchange exchanges keys securely using HMAC and SHA-256
func SecureKeyExchange(senderKey, receiverKey, data []byte) ([]byte, error) {
	hmac := GenerateHMAC(data, senderKey)
	if VerifyHMAC(data, receiverKey, hmac) {
		return hmac, nil
	}
	return nil, errors.New("key exchange verification failed")
}

// Test function to demonstrate the key management and exchange process
func main() {
	qkm := NewQuantumKeyManager()
	password := []byte("securepassword")
	chainID := "chain123"

	// Add a quantum key
	err := qkm.AddKey(chainID, password)
	if err != nil {
		fmt.Printf("Error adding key: %v\n", err)
		return
	}

	// Retrieve the quantum key
	key, err := qkm.GetKey(chainID)
	if err != nil {
		fmt.Printf("Error retrieving key: %v\n", err)
		return
	}
	fmt.Printf("Retrieved key: %s\n", hex.EncodeToString(key))

	// Simulate a quantum key exchange protocol
	// For demonstration, we'll use a local connection
	listener, err := net.Listen("tcp", "localhost:12345")
	if err != nil {
		fmt.Printf("Error setting up listener: %v\n", err)
		return
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Error accepting connection: %v\n", err)
			return
		}
		defer conn.Close()

		qkep, err := NewQuantumKeyExchangeProtocol(conn, password)
		if err != nil {
			fmt.Printf("Error setting up protocol: %v\n", err)
			return
		}

		err = qkep.ExchangeKeys()
		if err != nil {
			fmt.Printf("Error exchanging keys: %v\n", err)
			return
		}

		data := []byte("Important data")
		valid, err := qkep.VerifyKeyExchange(data)
		if err != nil {
			fmt.Printf("Error verifying key exchange: %v\n", err)
			return
		}
		fmt.Printf("Key exchange valid: %t\n", valid)
	}()

	conn, err := net.Dial("tcp", "localhost:12345")
	if err != nil {
		fmt.Printf("Error connecting: %v\n", err)
		return
	}
	defer conn.Close()

	qkep, err := NewQuantumKeyExchangeProtocol(conn, password)
	if err != nil {
		fmt.Printf("Error setting up protocol: %v\n", err)
		return
	}

	err = qkep.ExchangeKeys()
	if err != nil {
		fmt.Printf("Error exchanging keys: %v\n", err)
		return
	}

	data := []byte("Important data")
	valid, err := qkep.VerifyKeyExchange(data)
	if err != nil {
		fmt.Printf("Error verifying key exchange: %v\n", err)
		return
	}
	fmt.Printf("Key exchange valid: %t\n", valid)
}
