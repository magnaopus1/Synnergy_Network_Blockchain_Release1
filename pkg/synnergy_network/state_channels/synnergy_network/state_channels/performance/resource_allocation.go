package performance

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// ResourceAllocation represents the resource allocation settings
type ResourceAllocation struct {
	AllocationID   string
	NodeID         string
	ResourceType   string
	Allocated      int64
	Status         string
	Timestamp      time.Time
	lock           sync.RWMutex
}

const (
	AllocationActive   = "ACTIVE"
	AllocationInactive = "INACTIVE"
	AllocationFailed   = "FAILED"
)

// NewResourceAllocation initializes a new ResourceAllocation instance
func NewResourceAllocation(allocationID, nodeID, resourceType string, allocated int64) *ResourceAllocation {
	return &ResourceAllocation{
		AllocationID: allocationID,
		NodeID:       nodeID,
		ResourceType: resourceType,
		Allocated:    allocated,
		Status:       AllocationActive,
		Timestamp:    time.Now(),
	}
}

// UpdateAllocation updates the resource allocation
func (ra *ResourceAllocation) UpdateAllocation(resourceType string, allocated int64) error {
	ra.lock.Lock()
	defer ra.lock.Unlock()

	if ra.Status != AllocationActive {
		return errors.New("allocation is not active")
	}

	ra.ResourceType = resourceType
	ra.Allocated = allocated
	ra.Timestamp = time.Now()
	return nil
}

// DeactivateAllocation deactivates the resource allocation
func (ra *ResourceAllocation) DeactivateAllocation() error {
	ra.lock.Lock()
	defer ra.lock.Unlock()

	if ra.Status != AllocationActive {
		return errors.New("allocation is not active")
	}

	ra.Status = AllocationInactive
	ra.Timestamp = time.Now()
	return nil
}

// ValidateAllocation validates the allocation details
func (ra *ResourceAllocation) ValidateAllocation() error {
	ra.lock.RLock()
	defer ra.lock.RUnlock()

	if ra.AllocationID == "" || ra.NodeID == "" || ra.ResourceType == "" {
		return errors.New("allocation ID, node ID, and resource type cannot be empty")
	}

	if ra.Allocated <= 0 {
		return errors.New("allocated amount must be greater than zero")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the allocation
func (ra *ResourceAllocation) UpdateTimestamp() {
	ra.lock.Lock()
	defer ra.lock.Unlock()
	ra.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the allocation
func (ra *ResourceAllocation) GetTimestamp() time.Time {
	ra.lock.RLock()
	defer ra.lock.RUnlock()
	return ra.Timestamp
}

// EncryptAllocation encrypts the allocation details
func (ra *ResourceAllocation) EncryptAllocation(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s|%d|%s|%s",
		ra.AllocationID, ra.NodeID, ra.ResourceType, ra.Allocated, ra.Status, ra.Timestamp)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAllocation decrypts the allocation details
func (ra *ResourceAllocation) DecryptAllocation(encryptedData string, key []byte) error {
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

	ra.AllocationID = parts[0]
	ra.NodeID = parts[1]
	ra.ResourceType = parts[2]
	ra.Allocated = utils.ParseInt64(parts[3])
	ra.Status = parts[4]
	ra.Timestamp = utils.ParseTime(parts[5])
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

func (ra *ResourceAllocation) String() string {
	return fmt.Sprintf("AllocationID: %s, Status: %s, Timestamp: %s", ra.AllocationID, ra.Status, ra.Timestamp)
}
