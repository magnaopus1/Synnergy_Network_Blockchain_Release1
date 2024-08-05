package node

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Proof represents a cryptographic proof
type Proof struct {
	ID        string
	Data      string
	Timestamp time.Time
}

// CacheEntry represents a single entry in the cache
type CacheEntry struct {
	Proof    Proof
	ExpireAt time.Time
}

// ProofCache manages the caching of zk-SNARK proofs
type ProofCache struct {
	cache      map[string]CacheEntry
	cacheMutex sync.RWMutex
	expiryTime time.Duration
}

// NewProofCache initializes a new ProofCache with a specified expiry time
func NewProofCache(expiryTime time.Duration) *ProofCache {
	return &ProofCache{
		cache:      make(map[string]CacheEntry),
		expiryTime: expiryTime,
	}
}

// AddProof adds a new proof to the cache
func (pc *ProofCache) AddProof(proof Proof) {
	pc.cacheMutex.Lock()
	defer pc.cacheMutex.Unlock()

	expireAt := time.Now().Add(pc.expiryTime)
	pc.cache[proof.ID] = CacheEntry{
		Proof:    proof,
		ExpireAt: expireAt,
	}
}

// GetProof retrieves a proof from the cache by ID
func (pc *ProofCache) GetProof(proofID string) (*Proof, error) {
	pc.cacheMutex.RLock()
	defer pc.cacheMutex.RUnlock()

	entry, exists := pc.cache[proofID]
	if !exists || time.Now().After(entry.ExpireAt) {
		return nil, errors.New("proof not found or expired")
	}

	return &entry.Proof, nil
}

// RemoveProof removes a proof from the cache by ID
func (pc *ProofCache) RemoveProof(proofID string) {
	pc.cacheMutex.Lock()
	defer pc.cacheMutex.Unlock()

	delete(pc.cache, proofID)
}

// ClearExpiredProofs clears expired proofs from the cache
func (pc *ProofCache) ClearExpiredProofs() {
	pc.cacheMutex.Lock()
	defer pc.cacheMutex.Unlock()

	for id, entry := range pc.cache {
		if time.Now().After(entry.ExpireAt) {
			delete(pc.cache, id)
		}
	}
}

// Securely encrypts the proof data before caching
func (pc *ProofCache) EncryptProofData(proofData string, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(proofData), nil)
	return fmt.Sprintf("%x", ciphertext), nil
}

// Decrypts the proof data retrieved from the cache
func (pc *ProofCache) DecryptProofData(encryptedData string, key string) (string, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Securely caches an encrypted proof
func (pc *ProofCache) SecurelyCacheProof(proof Proof, encryptionKey string) error {
	encryptedData, err := pc.EncryptProofData(proof.Data, encryptionKey)
	if err != nil {
		return err
	}

	secureProof := Proof{
		ID:        proof.ID,
		Data:      encryptedData,
		Timestamp: proof.Timestamp,
	}

	pc.AddProof(secureProof)
	return nil
}

// Retrieves and decrypts a proof from the cache securely
func (pc *ProofCache) RetrieveSecureProof(proofID string, encryptionKey string) (*Proof, error) {
	proof, err := pc.GetProof(proofID)
	if err != nil {
		return nil, err
	}

	decryptedData, err := pc.DecryptProofData(proof.Data, encryptionKey)
	if err != nil {
		return nil, err
	}

	proof.Data = decryptedData
	return proof, nil
}
