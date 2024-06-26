package novel_features

import (
	"testing"
	"time"
	"encoding/base64"
	"github.com/stretchr/testify/assert"
)

// TestQuantumKeyPool tests the functionality of QuantumKeyPool
func TestQuantumKeyPool(t *testing.T) {
	keyPool := NewQuantumKeyPool(5)

	// Test adding keys to the pool
	for i := 0; i < 5; i++ {
		key, err := GenerateQuantumKey()
		assert.NoError(t, err, "Failed to generate quantum key")
		err = keyPool.AddKey(key)
		assert.NoError(t, err, "Failed to add key to pool")
	}

	// Test exceeding pool capacity
	key, err := GenerateQuantumKey()
	assert.NoError(t, err, "Failed to generate quantum key")
	err = keyPool.AddKey(key)
	assert.Error(t, err, "Expected error when adding key to full pool")

	// Test retrieving keys from the pool
	for i := 0; i < 5; i++ {
		quantumKey, err := keyPool.GetKey()
		assert.NoError(t, err, "Failed to retrieve key from pool")
		assert.NotNil(t, quantumKey, "Retrieved key should not be nil")
	}

	// Test retrieving key from empty pool
	quantumKey, err := keyPool.GetKey()
	assert.Error(t, err, "Expected error when retrieving key from empty pool")
	assert.Nil(t, quantumKey, "Retrieved key should be nil")
}

// TestQuantumSecureChannel tests the functionality of QuantumSecureChannel
func TestQuantumSecureChannel(t *testing.T) {
	key, err := GenerateQuantumKey()
	assert.NoError(t, err, "Failed to generate quantum key")

	qsc := NewQuantumSecureChannel(key)

	// Test encryption and decryption
	plaintext := "Hello, Quantum World!"
	encrypted, err := qsc.Encrypt(plaintext)
	assert.NoError(t, err, "Failed to encrypt message")

	decrypted, err := qsc.Decrypt(encrypted)
	assert.NoError(t, err, "Failed to decrypt message")
	assert.Equal(t, plaintext, decrypted, "Decrypted message should match the original plaintext")
}

// TestQuantumSecureMessaging tests the functionality of QuantumSecureMessaging
func TestQuantumSecureMessaging(t *testing.T) {
	keyPool := NewQuantumKeyPool(5)

	for i := 0; i < 5; i++ {
		key, err := GenerateQuantumKey()
		assert.NoError(t, err, "Failed to generate quantum key")
		err = keyPool.AddKey(key)
		assert.NoError(t, err, "Failed to add key to pool")
	}

	secureMessaging := NewQuantumSecureMessaging()

	// Get a key from the pool
	key, err := keyPool.GetKey()
	assert.NoError(t, err, "Failed to retrieve key from pool")

	channelID := "channel-1"
	secureMessaging.CreateChannel(channelID, key.Key)

	// Send and receive a message
	message := "Hello, Quantum Messaging!"
	encryptedMessage, err := secureMessaging.SendMessage(channelID, message)
	assert.NoError(t, err, "Failed to send message")

	decryptedMessage, err := secureMessaging.ReceiveMessage(channelID, encryptedMessage)
	assert.NoError(t, err, "Failed to receive message")
	assert.Equal(t, message, decryptedMessage, "Received message should match the original message")
}

// Test Quantum Random Number Generation
func TestQuantumRandomNumberGeneration(t *testing.T) {
	quantumRandom := NewQuantumRandom()

	// Generate a quantum random number
	randomNumber, err := quantumRandom.Generate()
	assert.NoError(t, err, "Failed to generate quantum random number")
	assert.NotNil(t, randomNumber, "Quantum random number should not be nil")
}

// Test Quantum-Enhanced Smart Contracts
func TestQuantumEnhancedSmartContracts(t *testing.T) {
	contract := NewQuantumSmartContract()

	// Set up a quantum-enhanced smart contract
	err := contract.Setup()
	assert.NoError(t, err, "Failed to set up quantum-enhanced smart contract")

	// Execute the smart contract
	result, err := contract.Execute()
	assert.NoError(t, err, "Failed to execute quantum-enhanced smart contract")
	assert.NotNil(t, result, "Execution result should not be nil")
}

// Test Quantum Key Pools
func TestQuantumKeyPools(t *testing.T) {
	keyPool := NewQuantumKeyPool(5)

	// Add keys to the pool
	for i := 0; i < 5; i++ {
		key, err := GenerateQuantumKey()
		assert.NoError(t, err, "Failed to generate quantum key")
		err = keyPool.AddKey(key)
		assert.NoError(t, err, "Failed to add key to pool")
	}

	// Test key allocation
	for i := 0; i < 5; i++ {
		quantumKey, err := keyPool.GetKey()
		assert.NoError(t, err, "Failed to retrieve key from pool")
		assert.NotNil(t, quantumKey, "Retrieved key should not be nil")
	}
}

// Test Privacy-Preserving Computation
func TestPrivacyPreservingComputation(t *testing.T) {
	computation := NewPrivacyPreservingComputation()

	// Perform a privacy-preserving computation
	result, err := computation.Execute("encrypted input")
	assert.NoError(t, err, "Failed to execute privacy-preserving computation")
	assert.NotNil(t, result, "Computation result should not be nil")
}

// Test Quantum-Secure Communication Channels
func TestQuantumSecureCommunicationChannels(t *testing.T) {
	messaging := NewQuantumSecureMessaging()

	// Create a secure channel
	channelID := "secure-channel"
	key, err := GenerateQuantumKey()
	assert.NoError(t, err, "Failed to generate quantum key")
	messaging.CreateChannel(channelID, key)

	// Send and receive a secure message
	message := "Secure Quantum Message"
	encryptedMessage, err := messaging.SendMessage(channelID, message)
	assert.NoError(t, err, "Failed to send secure message")

	decryptedMessage, err := messaging.ReceiveMessage(channelID, encryptedMessage)
	assert.NoError(t, err, "Failed to receive secure message")
	assert.Equal(t, message, decryptedMessage, "Decrypted message should match the original message")
}

// main function to run tests
func TestMain(m *testing.M) {
	// Run tests
	m.Run()
}
