package enhancedsmartcontractdebugger

import (
	"crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDebugContract(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	assert.NoError(t, err, "Key generation should not fail")

	debugger := NewDebugger(key, "test_log.txt")
	defer os.Remove("test_log.txt") // Clean up after test

	// Test empty contract code
	_, err = debugger.DebugContract("")
	assert.Error(t, err, "Should return error for empty contract code")

	// Test valid contract code
	result, err := debugger.DebugContract("valid code")
	assert.NoError(t, err, "Should not return an error for valid contract code")
	assert.Equal(t, "Execution successful", result, "Unexpected result for valid code")
}

func TestEncryptAndLog(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	assert.NoError(t, err, "Key generation should not fail")

	debugger := NewDebugger(key, "test_encrypted_log.txt")
	defer os.Remove("test_encrypted_log.txt") // Clean up after test

	err = debugger.encryptAndLog("Test log message")
	assert.NoError(t, err, "Logging should not fail and should encrypt log message")

	logContents, _ := os.ReadFile("test_encrypted_log.txt")
	assert.NotEqual(t, "Test log message", string(logContents), "Log contents should be encrypted")
}

func TestReadLogs(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	assert.NoError(t, err, "Key generation should not fail")

	debugger := NewDebugger(key, "test_log_read.txt")
	defer os.Remove("test_log_read.txt") // Clean up after test

	expectedLog := "This is a test log message"
	debugger.encryptAndLog(expectedLog) // Encrypt and log

	readLog, err := debugger.ReadLogs()
	assert.NoError(t, err, "Reading logs should not fail")
	assert.Equal(t, expectedLog, readLog, "Decrypted log should match the original message")
}

func TestEncryptionDecryption(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	assert.NoError(t, err, "Key generation should not fail")

	debugger := NewDebugger(key, "dummy_path")

	// Test encryption
	data := "Sensitive data"
	encryptedData, err := debugger.encrypt([]byte(data))
	assert.NoError(t, err, "Encryption should not fail")

	// Test decryption
	decryptedData, err := debugger.decrypt(encryptedData)
	assert.NoError(t, err, "Decryption should not fail")
	assert.Equal(t, data, string(decryptedData), "Decrypted data should match the original data")
}
