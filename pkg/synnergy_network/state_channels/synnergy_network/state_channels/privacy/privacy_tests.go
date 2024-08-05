package privacy

import (
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

func TestConfidentialTransaction(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	password := []byte("test_password")
	key, err := GenerateKey(password, salt, true)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	ct := NewConfidentialTransaction("txn123", "sender456", "receiver789", 100.50)

	encryptedData, err := ct.EncryptTransaction(key)
	if err != nil {
		t.Fatalf("Failed to encrypt transaction: %v", err)
	}

	decryptedCT := &ConfidentialTransaction{}
	err = decryptedCT.DecryptTransaction(encryptedData, key)
	if err != nil {
		t.Fatalf("Failed to decrypt transaction: %v", err)
	}

	if decryptedCT.TransactionID != ct.TransactionID || decryptedCT.Amount != ct.Amount {
		t.Fatalf("Decrypted transaction does not match original")
	}

	if err := ct.CompleteTransaction(); err != nil {
		t.Fatalf("Failed to complete transaction: %v", err)
	}

	if ct.Status != TransactionCompleted {
		t.Fatalf("Transaction status not updated to completed")
	}

	if err := ct.FailTransaction(); err == nil {
		t.Fatalf("Expected error when failing a completed transaction, got nil")
	}
}

type PrivacyTest struct {
	TestID     string
	NodeID     string
	TestType   string
	Status     string
	Result     string
	Timestamp  time.Time
	lock       sync.RWMutex
}

const (
	TestPending   = "PENDING"
	TestCompleted = "COMPLETED"
	TestFailed    = "FAILED"
)

func NewPrivacyTest(testID, nodeID, testType string) *PrivacyTest {
	return &PrivacyTest{
		TestID:    testID,
		NodeID:    nodeID,
		TestType:  testType,
		Status:    TestPending,
		Timestamp: time.Now(),
	}
}

func (pt *PrivacyTest) CompleteTest(result string) error {
	pt.lock.Lock()
	defer pt.lock.Unlock()

	if pt.Status != TestPending {
		return errors.New("test is not pending")
	}

	pt.Result = result
	pt.Status = TestCompleted
	pt.Timestamp = time.Now()
	return nil
}

func (pt *PrivacyTest) FailTest() error {
	pt.lock.Lock()
	defer pt.lock.Unlock()

	if pt.Status != TestPending {
		return errors.New("test is not pending")
	}

	pt.Status = TestFailed
	pt.Timestamp = time.Now()
	return nil
}

func (pt *PrivacyTest) EncryptTest(key []byte) (string, error) {
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

func (pt *PrivacyTest) DecryptTest(encryptedData string, key []byte) error {
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

func TestPrivacyTest(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	password := []byte("test_password")
	key, err := GenerateKey(password, salt, true)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	pt := NewPrivacyTest("test123", "node456", "confidentiality")

	encryptedData, err := pt.EncryptTest(key)
	if err != nil {
		t.Fatalf("Failed to encrypt test: %v", err)
	}

	decryptedPT := &PrivacyTest{}
	err = decryptedPT.DecryptTest(encryptedData, key)
	if err != nil {
		t.Fatalf("Failed to decrypt test: %v", err)
	}

	if decryptedPT.TestID != pt.TestID || decryptedPT.TestType != pt.TestType {
		t.Fatalf("Decrypted test does not match original")
	}

	if err := pt.CompleteTest("success"); err != nil {
		t.Fatalf("Failed to complete test: %v", err)
	}

	if pt.Status != TestCompleted {
		t.Fatalf("Test status not updated to completed")
	}

	if err := pt.FailTest(); err == nil {
		t.Fatalf("Expected error when failing a completed test, got nil")
	}
}
