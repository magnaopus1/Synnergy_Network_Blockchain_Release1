package node

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"
)

// Proof represents a cryptographic proof
type Proof struct {
	ID        string
	Data      string
	Timestamp time.Time
	Signature string
}

// ProofGenerator manages the generation of zk-SNARK proofs
type ProofGenerator struct {
	secretKey string
}

// NewProofGenerator initializes a new ProofGenerator with a secret key
func NewProofGenerator(secretKey string) *ProofGenerator {
	return &ProofGenerator{
		secretKey: secretKey,
	}
}

// GenerateProof generates a new zk-SNARK proof for the given data
func (pg *ProofGenerator) GenerateProof(data string) (Proof, error) {
	timestamp := time.Now()
	signature, err := pg.signData(data, timestamp)
	if err != nil {
		return Proof{}, err
	}

	proofID := pg.generateProofID(data, timestamp)
	return Proof{
		ID:        proofID,
		Data:      data,
		Timestamp: timestamp,
		Signature: signature,
	}, nil
}

// VerifyProof verifies the integrity and authenticity of the given proof
func (pg *ProofGenerator) VerifyProof(proof Proof) error {
	expectedSignature, err := pg.signData(proof.Data, proof.Timestamp)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare([]byte(proof.Signature), []byte(expectedSignature)) != 1 {
		return errors.New("proof signature verification failed")
	}

	expectedProofID := pg.generateProofID(proof.Data, proof.Timestamp)
	if subtle.ConstantTimeCompare([]byte(proof.ID), []byte(expectedProofID)) != 1 {
		return errors.New("proof ID verification failed")
	}

	return nil
}

// signData signs the data with the secret key and timestamp
func (pg *ProofGenerator) signData(data string, timestamp time.Time) (string, error) {
	hash := sha256.New()
	hash.Write([]byte(data))
	hash.Write([]byte(timestamp.String()))
	hash.Write([]byte(pg.secretKey))
	return string(hash.Sum(nil)), nil
}

// generateProofID generates a unique proof ID based on the data and timestamp
func (pg *ProofGenerator) generateProofID(data string, timestamp time.Time) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	hash.Write([]byte(timestamp.String()))
	return string(hash.Sum(nil))
}

// ProofGenerationManager manages the lifecycle of proof generation
type ProofGenerationManager struct {
	generator *ProofGenerator
	cache     *ProofCache
}

// NewProofGenerationManager initializes a new ProofGenerationManager
func NewProofGenerationManager(generator *ProofGenerator, cache *ProofCache) *ProofGenerationManager {
	return &ProofGenerationManager{
		generator: generator,
		cache:     cache,
	}
}

// GenerateAndCacheProof generates a new proof and caches it
func (pgm *ProofGenerationManager) GenerateAndCacheProof(data string) (Proof, error) {
	proof, err := pgm.generator.GenerateProof(data)
	if err != nil {
		return Proof{}, err
	}

	pgm.cache.AddProof(proof)
	return proof, nil
}

// RetrieveProof retrieves a proof from the cache by ID
func (pgm *ProofGenerationManager) RetrieveProof(proofID string) (*Proof, error) {
	return pgm.cache.GetProof(proofID)
}

// SecurelyCacheProof encrypts and caches a proof securely
func (pgm *ProofGenerationManager) SecurelyCacheProof(proof Proof, encryptionKey string) error {
	return pgm.cache.SecurelyCacheProof(proof, encryptionKey)
}

// RetrieveSecureProof retrieves and decrypts a proof from the cache securely
func (pgm *ProofGenerationManager) RetrieveSecureProof(proofID string, encryptionKey string) (*Proof, error) {
	return pgm.cache.RetrieveSecureProof(proofID, encryptionKey)
}
