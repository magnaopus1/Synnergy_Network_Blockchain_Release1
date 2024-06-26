package data_protection

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAESEncryptionDecryption(t *testing.T) {
	originalText := []byte("Test data for AES encryption and decryption")

	// Generate a new AES key
	aesKey, err := GenerateAESKey()
	assert.NoError(t, err, "Error generating AES key")

	// Encrypt the data
	ciphertext, err := EncryptAES(originalText, aesKey)
	assert.NoError(t, err, "Error encrypting data with AES")

	// Decrypt the data
	plaintext, err := DecryptAES(ciphertext, aesKey)
	assert.NoError(t, err, "Error decrypting data with AES")
	assert.Equal(t, originalText, plaintext, "Decrypted text does not match original")
}

func TestRSAEncryptionDecryption(t *testing.T) {
	originalText := []byte("Test data for RSA encryption and decryption")

	// Generate RSA keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err, "Error generating RSA private key")
	publicKey := &privateKey.PublicKey

	// Encrypt the data
	ciphertext, err := EncryptRSA(originalText, publicKey)
	assert.NoError(t, err, "Error encrypting data with RSA")

	// Decrypt the data
	plaintext, err := DecryptRSA(ciphertext, privateKey)
	assert.NoError(t, err, "Error decrypting data with RSA")
	assert.Equal(t, originalText, plaintext, "Decrypted text does not match original")
}

func TestTLSConnection(t *testing.T) {
	// Generate TLS certificates
	cert, err := GenerateTLSCert()
	assert.NoError(t, err, "Error generating TLS certificate")

	// Check if the certificate is valid
	_, err = x509.ParseCertificate(cert.Certificate[0])
	assert.NoError(t, err, "Error parsing TLS certificate")
}

func TestKeyManagement(t *testing.T) {
	// Generate RSA keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err, "Error generating RSA private key")
	publicKey := &privateKey.PublicKey

	// Export the keys
	privateKeyPEM, err := ExportRSAPrivateKey(privateKey)
	assert.NoError(t, err, "Error exporting RSA private key")
	publicKeyPEM, err := ExportRSAPublicKey(publicKey)
	assert.NoError(t, err, "Error exporting RSA public key")

	// Import the keys
	importedPrivateKey, err := ImportRSAPrivateKey(privateKeyPEM)
	assert.NoError(t, err, "Error importing RSA private key")
	importedPublicKey, err := ImportRSAPublicKey(publicKeyPEM)
	assert.NoError(t, err, "Error importing RSA public key")

	// Check if the imported keys are valid
	assert.Equal(t, privateKey, importedPrivateKey, "Imported private key does not match original")
	assert.Equal(t, publicKey, importedPublicKey, "Imported public key does not match original")
}

func TestZeroKnowledgeProofs(t *testing.T) {
	secret := big.NewInt(12345)
	z := NewZeroKnowledgeProofs(secret)

	err := z.GenerateProof()
	assert.NoError(t, err, "Error generating zero-knowledge proof")

	valid, err := z.VerifyProof()
	assert.NoError(t, err, "Error verifying zero-knowledge proof")
	assert.True(t, valid, "Zero-knowledge proof is not valid")

	proofBytes, err := z.SerializeProof()
	assert.NoError(t, err, "Error serializing zero-knowledge proof")

	newZ := NewZeroKnowledgeProofs(secret)
	err = newZ.DeserializeProof(proofBytes)
	assert.NoError(t, err, "Error deserializing zero-knowledge proof")

	valid, err = newZ.VerifyProof()
	assert.NoError(t, err, "Error verifying deserialized zero-knowledge proof")
	assert.True(t, valid, "Deserialized zero-knowledge proof is not valid")

	hash, err := z.HashProof()
	assert.NoError(t, err, "Error hashing zero-knowledge proof")
	assert.NotEmpty(t, hash, "Zero-knowledge proof hash is empty")
}
