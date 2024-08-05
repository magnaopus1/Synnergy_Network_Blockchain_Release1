package performance

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// ShardingPartitioning represents the sharding and partitioning settings
type ShardingPartitioning struct {
	ShardID     string
	NodeID      string
	PartitionID string
	Status      string
	Timestamp   time.Time
	lock        sync.RWMutex
}

const (
	ShardActive   = "ACTIVE"
	ShardInactive = "INACTIVE"
	ShardFailed   = "FAILED"
)

// NewShardingPartitioning initializes a new ShardingPartitioning instance
func NewShardingPartitioning(shardID, nodeID, partitionID string) *ShardingPartitioning {
	return &ShardingPartitioning{
		ShardID:     shardID,
		NodeID:      nodeID,
		PartitionID: partitionID,
		Status:      ShardActive,
		Timestamp:   time.Now(),
	}
}

// UpdateSharding updates the sharding settings
func (sp *ShardingPartitioning) UpdateSharding(partitionID string) error {
	sp.lock.Lock()
	defer sp.lock.Unlock()

	if sp.Status != ShardActive {
		return errors.New("shard is not active")
	}

	sp.PartitionID = partitionID
	sp.Timestamp = time.Now()
	return nil
}

// DeactivateSharding deactivates the sharding
func (sp *ShardingPartitioning) DeactivateSharding() error {
	sp.lock.Lock()
	defer sp.lock.Unlock()

	if sp.Status != ShardActive {
		return errors.New("shard is not active")
	}

	sp.Status = ShardInactive
	sp.Timestamp = time.Now()
	return nil
}

// ValidateSharding validates the sharding details
func (sp *ShardingPartitioning) ValidateSharding() error {
	sp.lock.RLock()
	defer sp.lock.RUnlock()

	if sp.ShardID == "" || sp.NodeID == "" || sp.PartitionID == "" {
		return errors.New("shard ID, node ID, and partition ID cannot be empty")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the sharding
func (sp *ShardingPartitioning) UpdateTimestamp() {
	sp.lock.Lock()
	defer sp.lock.Unlock()
	sp.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the sharding
func (sp *ShardingPartitioning) GetTimestamp() time.Time {
	sp.lock.RLock()
	defer sp.lock.RUnlock()
	return sp.Timestamp
}

// EncryptSharding encrypts the sharding details
func (sp *ShardingPartitioning) EncryptSharding(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s|%s|%s",
		sp.ShardID, sp.NodeID, sp.PartitionID, sp.Status, sp.Timestamp)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSharding decrypts the sharding details
func (sp *ShardingPartitioning) DecryptSharding(encryptedData string, key []byte) error {
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
	if len(parts) != 5 {
		return errors.New("invalid encrypted data format")
	}

	sp.ShardID = parts[0]
	sp.NodeID = parts[1]
	sp.PartitionID = parts[2]
	sp.Status = parts[3]
	sp.Timestamp = utils.ParseTime(parts[4])
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

func (sp *ShardingPartitioning) String() string {
	return fmt.Sprintf("ShardID: %s, Status: %s, Timestamp: %s", sp.ShardID, sp.Status, sp.Timestamp)
}
