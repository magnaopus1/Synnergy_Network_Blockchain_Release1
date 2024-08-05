package privacy

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// ZeroKnowledgeProof represents zero-knowledge proof settings
type ZeroKnowledgeProof struct {
	ProofID      string
	NodeID       string
	Statement    string
	Proof        string
	Status       string
	Timestamp    time.Time
	lock         sync.RWMutex
}

const (
	ProofPending   = "PENDING"
	ProofVerified  = "VERIFIED"
	ProofFailed    = "FAILED"
)

// NewZeroKnowledgeProof initializes a new ZeroKnowledgeProof instance
func NewZeroKnowledgeProof(proofID, nodeID, statement, proof string) *ZeroKnowledgeProof {
	return &ZeroKnowledgeProof{
		ProofID:   proofID,
		NodeID:    nodeID,
		Statement: statement,
		Proof:     proof,
		Status:    ProofPending,
		Timestamp: time.Now(),
	}
}

// VerifyProof verifies the zero-knowledge proof
func (zkp *ZeroKnowledgeProof) VerifyProof() error {
	zkp.lock.Lock()
	defer zkp.lock.Unlock()

	if zkp.Status != ProofPending {
		return errors.New("proof is not pending")
	}

	// Placeholder for proof verification logic
	if zkp.Proof == "" {
		zkp.Status = ProofFailed
		zkp.Timestamp = time.Now()
		return errors.New("proof verification failed")
	}

	zkp.Status = ProofVerified
	zkp.Timestamp = time.Now()
	return nil
}

// FailProof marks the proof as failed
func (zkp *ZeroKnowledgeProof) FailProof() error {
	zkp.lock.Lock()
	defer zkp.lock.Unlock()

	if zkp.Status != ProofPending {
		return errors.New("proof is not pending")
	}

	zkp.Status = ProofFailed
	zkp.Timestamp = time.Now()
	return nil
}

// EncryptProof encrypts the proof details
func (zkp *ZeroKnowledgeProof) EncryptProof(key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		zkp.ProofID, zkp.NodeID, zkp.Statement, zkp.Proof, zkp.Status, zkp.Timestamp)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptProof decrypts the proof details
func (zkp *ZeroKnowledgeProof) DecryptProof(encryptedData string, key []byte) error {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	data, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	parts := utils.Split(string(data), '|')
	if len(parts) != 6 {
		return errors.New("invalid encrypted data format")
	}

	zkp.ProofID = parts[0]
	zkp.NodeID = parts[1]
	zkp.Statement = parts[2]
	zkp.Proof = parts[3]
	zkp.Status = parts[4]
	zkp.Timestamp = utils.ParseTime(parts[5])
	return nil
}

// GenerateKey generates a cryptographic key using Argon2
func GenerateKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// GenerateSalt generates a cryptographic salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// HashData hashes the data using SHA-256
func HashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (zkp *ZeroKnowledgeProof) String() string {
	return fmt.Sprintf("ProofID: %s, Statement: %s, Proof: %s, Status: %s, Timestamp: %s",
		zkp.ProofID, zkp.Statement, zkp.Proof, zkp.Status, zkp.Timestamp)
}
