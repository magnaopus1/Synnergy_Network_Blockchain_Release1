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

// SignData signs the data using the provided key
func SignData(data, key []byte) ([]byte, error) {
	hmac := GenerateHMAC(data, key)
	return hmac, nil
}

// VerifySignature verifies the signature of the data using the provided key
func VerifySignature(data, key, signature []byte) bool {
	return VerifyHMAC(data, key, signature)
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

// GenerateKeyPair generates a public-private key pair for quantum key distribution
func GenerateKeyPair() ([]byte, []byte, error) {
	privateKey, err := GenerateRandomBytes(Argon2KeyLen)
	if err != nil {
		return nil, nil, err
	}
	publicKey := sha256.Sum256(privateKey)
	return privateKey, publicKey[:], nil
}

// VerifyKeyPair verifies that a given public key matches the private key
func VerifyKeyPair(privateKey, publicKey []byte) bool {
	expectedPublicKey := sha256.Sum256(privateKey)
	return hmac.Equal(expectedPublicKey[:], publicKey)
}

// SecureKeyExchange exchanges keys securely using HMAC and SHA-256
func SecureKeyExchange(senderKey, receiverKey, data []byte) ([]byte, error) {
	hmac := GenerateHMAC(data, senderKey)
	if VerifyHMAC(data, receiverKey, hmac) {
		return hmac, nil
	}
	return nil, errors.New("key exchange verification failed")
}


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


// NewSecureKeyManager creates a new SecureKeyManager
func NewSecureKeyManager() *SecureKeyManager {
	return &SecureKeyManager{
		keys: make(map[string][]byte),
	}
}

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

// Encrypt encrypts data using AES-GCM
func Encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := GenerateRandomBytes(aesGCM.NonceSize())
	if err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-GCM
func Decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
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

// AddKey adds a quantum key for a given chain ID
func (skm *SecureKeyManager) AddKey(chainID string, password []byte) error {
	salt, err := GenerateRandomBytes(SaltLen)
	if err != nil {
		return err
	}

	key := GenerateArgon2Key(password, salt)
	skm.mu.Lock()
	defer skm.mu.Unlock()
	skm.keys[chainID] = key
	return nil
}

// GetKey retrieves the quantum key for a given chain ID
func (skm *SecureKeyManager) GetKey(chainID string) ([]byte, error) {
	skm.mu.Lock()
	defer skm.mu.Unlock()
	key, exists := skm.keys[chainID]
	if !exists {
		return nil, errors.New("key not found")
	}
	return key, nil
}

// DeleteKey deletes the quantum key for a given chain ID
func (skm *SecureKeyManager) DeleteKey(chainID string) {
	skm.mu.Lock()
	defer skm.mu.Unlock()
	delete(skm.keys, chainID)
}

// UpdateKey updates the quantum key for a given chain ID
func (skm *SecureKeyManager) UpdateKey(chainID string, newPassword []byte) error {
	salt, err := GenerateRandomBytes(SaltLen)
	if err != nil {
		return err
	}

	key := GenerateArgon2Key(newPassword, salt)
	skm.mu.Lock()
	defer skm.mu.Unlock()
	skm.keys[chainID] = key
	return nil
}

// EncryptWithChainID encrypts data using the key for a given chain ID
func (skm *SecureKeyManager) EncryptWithChainID(chainID string, data []byte) ([]byte, error) {
	key, err := skm.GetKey(chainID)
	if err != nil {
		return nil, err
	}
	return Encrypt(data, key)
}

// DecryptWithChainID decrypts data using the key for a given chain ID
func (skm *SecureKeyManager) DecryptWithChainID(chainID string, data []byte) ([]byte, error) {
	key, err := skm.GetKey(chainID)
	if err != nil {
		return nil, err
	}
	return Decrypt(data, key)
}

