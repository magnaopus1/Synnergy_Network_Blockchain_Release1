package mobile_node_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/synnergy_network/mobile_node"
)

// Test Initialization
func TestMobileNodeInitialization(t *testing.T) {
	node := mobile_node.NewMobileNode()
	assert.NotNil(t, node, "MobileNode should be initialized")
}

// Test Encryption Key Generation
func TestEncryptionKeyGeneration(t *testing.T) {
	node := mobile_node.NewMobileNode()
	password := []byte("supersecurepassword")
	salt := []byte("somesalt")

	key, err := node.GenerateEncryptionKey(password, salt)
	assert.NoError(t, err, "Encryption key generation should not produce an error")
	assert.NotNil(t, key, "Encryption key should not be nil")
}

// Test Data Encryption and Decryption
func TestEncryptDecryptData(t *testing.T) {
	node := mobile_node.NewMobileNode()
	password := []byte("supersecurepassword")
	salt := []byte("somesalt")

	key, err := node.GenerateEncryptionKey(password, salt)
	assert.NoError(t, err, "Encryption key generation should not produce an error")
	assert.NotNil(t, key, "Encryption key should not be nil")

	plaintext := []byte("This is a test")
	ciphertext, err := node.EncryptData(plaintext)
	assert.NoError(t, err, "Data encryption should not produce an error")
	assert.NotNil(t, ciphertext, "Ciphertext should not be nil")

	decrypted, err := node.DecryptData(ciphertext)
	assert.NoError(t, err, "Data decryption should not produce an error")
	assert.Equal(t, plaintext, decrypted, "Decrypted data should match the original plaintext")
}

// Test Blockchain Data Syncing
func TestSyncBlockchainData(t *testing.T) {
	node := mobile_node.NewMobileNode()
	dataChunk := []byte("blockchain data chunk")

	node.SyncBlockchainData(dataChunk)
	assert.Contains(t, node.GetBlockchainData(), dataChunk, "Blockchain data should contain the synced chunk")
	assert.WithinDuration(t, time.Now(), node.GetLastSyncTime(), time.Second, "Last sync time should be updated")
}

// Test User Registration and Authentication
func TestUserRegistrationAndAuthentication(t *testing.T) {
	node := mobile_node.NewMobileNode()
	username := "testuser"
	password := "securepassword"

	node.RegisterUser(username, password)
	assert.Contains(t, node.GetUserCredentials(), username, "User credentials should contain the registered user")

	authenticated := node.AuthenticateUser(username, password)
	assert.True(t, authenticated, "User should be authenticated with correct credentials")

	authenticated = node.AuthenticateUser(username, "wrongpassword")
	assert.False(t, authenticated, "User should not be authenticated with incorrect credentials")
}

// Test Transaction Signing and Verification
func TestSignVerifyTransaction(t *testing.T) {
	node := mobile_node.NewMobileNode()
	privateKey, _ := mobile_node.GenerateRSAKeyPair()
	publicKey := &privateKey.PublicKey
	transaction := []byte("transaction data")

	signature, err := node.SignTransaction(privateKey, transaction)
	assert.NoError(t, err, "Transaction signing should not produce an error")
	assert.NotNil(t, signature, "Signature should not be nil")

	err = node.VerifyTransaction(publicKey, transaction, signature)
	assert.NoError(t, err, "Transaction verification should not produce an error")

	err = node.VerifyTransaction(publicKey, transaction, []byte("invalid signature"))
	assert.Error(t, err, "Transaction verification should fail with invalid signature")
}

// Test Proof Generation and Verification
func TestProofGenerationAndVerification(t *testing.T) {
	node := mobile_node.NewMobileNode()
	transactionData := []byte("transaction data")

	proof, err := node.GenerateProof(transactionData)
	assert.NoError(t, err, "Proof generation should not produce an error")
	assert.NotNil(t, proof, "Proof should not be nil")

	valid, err := node.VerifyProof(proof, transactionData)
	assert.NoError(t, err, "Proof verification should not produce an error")
	assert.True(t, valid, "Proof should be valid for the given transaction data")
}

// Test Health Check
func TestHealthCheck(t *testing.T) {
	node := mobile_node.NewMobileNode()
	node.AuthenticateUser("testuser", "securepassword")
	node.SyncBlockchainData([]byte("blockchain data"))

	err := node.HealthCheck()
	assert.NoError(t, err, "Health check should pass for a properly configured node")
}
