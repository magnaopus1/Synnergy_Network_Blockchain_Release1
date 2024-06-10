package emergency_broadcast_system

import (
	"bytes"
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestBroadcastMessage checks the broadcast functionality with a valid message.
func TestBroadcastMessage(t *testing.T) {
	key := make([]byte, 16) // AES-128 for simplicity in testing
	broadcaster := NewBroadcaster(key)

	msg := EmergencyMessage{
		ID:        "EMG001",
		Message:   "Emergency alert: severe weather warning",
		Timestamp: time.Now(),
		Severity:  "high",
	}

	err := broadcaster.BroadcastMessage(msg)
	assert.Nil(t, err, "BroadcastMessage should not return an error")
}

// TestReceiveMessage validates the decryption and integrity of a received message.
func TestReceiveMessage(t *testing.T) {
	key := make([]byte, 16)
	broadcaster := NewBroadcaster(key)

	originalMessage := EmergencyMessage{
		ID:        "EMG002",
		Message:   "Emergency alert: evacuation notice",
		Timestamp: time.Now(),
		Severity:  "critical",
	}

	// Simulate sending message
	data, _ := json.Marshal(originalMessage)
	encryptedData, _ := broadcaster.encryptData(data)

	// Simulate receiving message
	receivedMessage, err := broadcaster.ReceiveMessage(encryptedData)
	assert.Nil(t, err, "ReceiveMessage should not return an error")
	assert.Equal(t, originalMessage.ID, receivedMessage.ID, "Received message ID should match the original")
	assert.Equal(t, originalMessage.Message, receivedMessage.Message, "Received message content should match the original")
}

// TestEncryptionDecryption checks the encryption and decryption processes for consistency.
func TestEncryptionDecryption(t *testing.T) {
	key := []byte("0123456789abcdef") // 16-byte key for AES-128
	broadcaster := NewBroadcaster(key)

	testData := []byte("Test data for encryption")
	encryptedData, encErr := broadcaster.encryptData(testData)
	assert.Nil(t, encErr, "Encryption should not return an error")

	decryptedData, decErr := broadcaster.decryptData(encryptedData)
	assert.Nil(t, decErr, "Decryption should not return an error")
	assert.True(t, bytes.Equal(testData, decryptedData), "Decrypted data should match original")
}

// TestInvalidKey ensures the system handles encryption and decryption errors due to invalid keys.
func TestInvalidKey(t *testing.T) {
	badKey := []byte("short") // intentionally bad key
	broadcaster := NewBroadcaster(badKey)

	_, encErr := broadcaster.encryptData([]byte("data"))
	assert.NotNil(t, encErr, "Encryption with an invalid key should fail")

	_, decErr := broadcaster.decryptData([]byte("data"))
	assert.NotNil(t, decErr, "Decryption with an invalid key should fail")
}
