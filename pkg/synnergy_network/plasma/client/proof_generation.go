package client

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
)

// Proof represents a proof of work or stake
type Proof struct {
    Type        string
    Data        string
    Hash        string
    Difficulty  int
    Nonce       int
    Timestamp   string
}

// ProofGenerator handles the generation and validation of proofs
type ProofGenerator struct {
    mu        sync.Mutex
    Blockchain *child_chain.Blockchain
}

// NewProofGenerator creates a new ProofGenerator
func NewProofGenerator(blockchain *child_chain.Blockchain) *ProofGenerator {
    return &ProofGenerator{
        Blockchain: blockchain,
    }
}

// GenerateProofOfWork generates a proof of work
func (pg *ProofGenerator) GenerateProofOfWork(data string, difficulty int) (*Proof, error) {
    pg.mu.Lock()
    defer pg.mu.Unlock()

    nonce := 0
    var hash string
    for {
        record := fmt.Sprintf("%s%d", data, nonce)
        hash = calculateHash(record)
        if isValidHash(hash, difficulty) {
            break
        }
        nonce++
    }

    proof := &Proof{
        Type:       "ProofOfWork",
        Data:       data,
        Hash:       hash,
        Difficulty: difficulty,
        Nonce:      nonce,
        Timestamp:  getCurrentTimestamp(),
    }

    return proof, nil
}

// GenerateProofOfStake generates a proof of stake
func (pg *ProofGenerator) GenerateProofOfStake(stakeholder string, amount int, difficulty int) (*Proof, error) {
    pg.mu.Lock()
    defer pg.mu.Unlock()

    record := fmt.Sprintf("%s%d", stakeholder, amount)
    hash := calculateHash(record)

    proof := &Proof{
        Type:       "ProofOfStake",
        Data:       record,
        Hash:       hash,
        Difficulty: difficulty,
        Nonce:      0,
        Timestamp:  getCurrentTimestamp(),
    }

    return proof, nil
}

// ValidateProof validates a given proof
func (pg *ProofGenerator) ValidateProof(proof *Proof) (bool, error) {
    pg.mu.Lock()
    defer pg.mu.Unlock()

    record := fmt.Sprintf("%s%d", proof.Data, proof.Nonce)
    hash := calculateHash(record)

    if hash != proof.Hash {
        return false, errors.New("invalid proof hash")
    }

    if !isValidHash(hash, proof.Difficulty) {
        return false, errors.New("proof does not meet difficulty requirement")
    }

    return true, nil
}

// calculateHash calculates the SHA-256 hash of the given data
func calculateHash(data string) string {
    hash := sha256.New()
    hash.Write([]byte(data))
    return hex.EncodeToString(hash.Sum(nil))
}

// isValidHash checks if the hash meets the difficulty requirement
func isValidHash(hash string, difficulty int) bool {
    prefix := ""
    for i := 0; i < difficulty; i++ {
        prefix += "0"
    }
    return hash[:difficulty] == prefix
}

// getCurrentTimestamp gets the current timestamp as a string
func getCurrentTimestamp() string {
    return fmt.Sprintf("%d", time.Now().Unix())
}
