package performance

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// PerformanceTest represents a performance test
type PerformanceTest struct {
	TestID       string
	NodeID       string
	TestType     string
	Status       string
	Result       string
	Timestamp    time.Time
	lock         sync.RWMutex
}

const (
	TestPending   = "PENDING"
	TestCompleted = "COMPLETED"
	TestFailed    = "FAILED"
)

// NewPerformanceTest initializes a new PerformanceTest instance
func NewPerformanceTest(testID, nodeID, testType string) *PerformanceTest {
	return &PerformanceTest{
		TestID:    testID,
		NodeID:    nodeID,
		TestType:  testType,
		Status:    TestPending,
		Timestamp: time.Now(),
	}
}

// ExecuteTest executes the performance test
func (pt *PerformanceTest) ExecuteTest() error {
	pt.lock.Lock()
	defer pt.lock.Unlock()

	if pt.Status != TestPending {
		return errors.New("test is not pending")
	}

	// Simulate test execution logic
	// This should include network performance, latency, bandwidth, etc.
	pt.Result = "Test executed successfully"
	pt.Status = TestCompleted
	pt.Timestamp = time.Now()
	return nil
}

// EncryptTest encrypts the test details
func (pt *PerformanceTest) EncryptTest(key []byte) (string, error) {
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
		pt.TestID, pt.NodeID, pt.TestType, pt.Status, pt.Result, pt.Timestamp)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptTest decrypts the test details
func (pt *PerformanceTest) DecryptTest(encryptedData string, key []byte) error {
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

	pt.TestID = parts[0]
	pt.NodeID = parts[1]
	pt.TestType = parts[2]
	pt.Status = parts[3]
	pt.Result = parts[4]
	pt.Timestamp = utils.ParseTime(parts[5])
	return nil
}

// GetTestDetails returns the details of the test
func (pt *PerformanceTest) GetTestDetails() (string, string, string, string, string, time.Time) {
	pt.lock.RLock()
	defer pt.lock.RUnlock()
	return pt.TestID, pt.NodeID, pt.TestType, pt.Status, pt.Result, pt.Timestamp
}

// ValidateTest validates the test details
func (pt *PerformanceTest) ValidateTest() error {
	pt.lock.RLock()
	defer pt.lock.RUnlock()

	if pt.TestID == "" || pt.NodeID == "" || pt.TestType == "" {
		return errors.New("test ID, node ID, and test type cannot be empty")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the test
func (pt *PerformanceTest) UpdateTimestamp() {
	pt.lock.Lock()
	defer pt.lock.Unlock()
	pt.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the test
func (pt *PerformanceTest) GetTimestamp() time.Time {
	pt.lock.RLock()
	defer pt.lock.RUnlock()
	return pt.Timestamp
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

func (pt *PerformanceTest) String() string {
	return fmt.Sprintf("TestID: %s, Status: %s, Timestamp: %s", pt.TestID, pt.Status, pt.Timestamp)
}
