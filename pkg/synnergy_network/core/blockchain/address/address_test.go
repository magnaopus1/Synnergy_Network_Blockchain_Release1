package address

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/scrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestGenerateAddress tests the address generation functionality
func TestGenerateAddress(t *testing.T) {
	address, err := GenerateAddress()
	assert.NoError(t, err, "Error generating address")
	assert.NotEmpty(t, address.Address, "Generated address should not be empty")
	assert.NotEmpty(t, address.PublicKey, "Public key should not be empty")
	assert.NotEmpty(t, address.PrivateKey, "Private key should not be empty")
}

// TestPublicKeyToAddress tests the public key to address conversion
func TestPublicKeyToAddress(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err, "Error generating private key")
	publicKey := append(privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes()...)
	address := PublicKeyToAddress(publicKey)
	assert.NotEmpty(t, address, "Address should not be empty")
}

// TestEncryptDecryptPrivateKey tests the encryption and decryption of the private key
func TestEncryptDecryptPrivateKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err, "Error generating private key")

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	assert.NoError(t, err, "Error marshaling private key")

	passphrase := "test-passphrase"
	encryptedKey, err := EncryptPrivateKey(hex.EncodeToString(privateKeyBytes), passphrase)
	assert.NoError(t, err, "Error encrypting private key")

	decryptedKey, err := DecryptPrivateKey(encryptedKey, passphrase)
	assert.NoError(t, err, "Error decrypting private key")

	assert.Equal(t, hex.EncodeToString(privateKeyBytes), decryptedKey, "Decrypted private key should match original")
}

// TestAddMetadata tests the addition of metadata to the address
func TestAddMetadata(t *testing.T) {
	address, err := GenerateAddress()
	assert.NoError(t, err, "Error generating address")

	address.AddMetadata("key1", "value1")
	assert.Contains(t, address.Metadata, "key1", "Metadata should contain the key 'key1'")
	assert.Contains(t, address.Metadata, "value1", "Metadata should contain the value 'value1'")
}

// TestToJSON tests the serialization of the address to JSON
func TestToJSON(t *testing.T) {
	address, err := GenerateAddress()
	assert.NoError(t, err, "Error generating address")

	jsonStr, err := address.ToJSON()
	assert.NoError(t, err, "Error converting address to JSON")
	assert.NotEmpty(t, jsonStr, "JSON string should not be empty")
}

// TestDatabaseOperations tests various database operations
func TestDatabaseOperations(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	assert.NoError(t, err, "Error initializing database")

	err = db.AutoMigrate(&Address{}, &BlacklistedAddress{}, &WhitelistedAddress{}, &Metadata{}, &CrossChainAddress{}, &AddressAnalytics{}, &Transaction{})
	assert.NoError(t, err, "Error migrating database")

	// Test blacklisting an address
	err = BlacklistAddress(db, "test-blacklist-address")
	assert.NoError(t, err, "Error blacklisting address")
	isBlacklisted, err := IsAddressBlacklisted(db, "test-blacklist-address")
	assert.NoError(t, err, "Error checking if address is blacklisted")
	assert.True(t, isBlacklisted, "Address should be blacklisted")

	// Test whitelisting an address
	err = WhitelistAddress(db, "test-whitelist-address")
	assert.NoError(t, err, "Error whitelisting address")
	isWhitelisted, err := IsAddressWhitelisted(db, "test-whitelist-address")
	assert.NoError(t, err, "Error checking if address is whitelisted")
	assert.True(t, isWhitelisted, "Address should be whitelisted")

	// Test adding metadata entry
	address, err := GenerateAddress()
	assert.NoError(t, err, "Error generating address")
	err = db.Create(&address).Error
	assert.NoError(t, err, "Error creating address in database")
	err = AddMetadataEntry(db, address.ID, "key", "value")
	assert.NoError(t, err, "Error adding metadata entry")
	metadata, err := GetMetadata(db, address.ID)
	assert.NoError(t, err, "Error getting metadata")
	assert.Equal(t, "value", metadata["key"], "Metadata value should match")

	// Test adding and retrieving cross-chain data
	crossChainData := map[string]string{"chain": "test-chain", "address": "cross-chain-address"}
	err = AddCrossChainData(db, address.Address, crossChainData)
	assert.NoError(t, err, "Error adding cross-chain data")
	retrievedData, err := GetCrossChainData(db, address.Address)
	assert.NoError(t, err, "Error retrieving cross-chain data")
	assert.Equal(t, crossChainData, retrievedData, "Cross-chain data should match")

	// Test adding and retrieving analytics data
	analyticsData := map[string]interface{}{"transactionCount": 10, "balance": 1000}
	err = AddAnalyticsData(db, address.ID, analyticsData)
	assert.NoError(t, err, "Error adding analytics data")
	retrievedAnalytics, err := GetAnalyticsData(db, address.ID)
	assert.NoError(t, err, "Error retrieving analytics data")
	assert.Equal(t, analyticsData, retrievedAnalytics, "Analytics data should match")
}

// TestSecureChannel tests the secure encrypted communication channels
func TestSecureChannel(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	assert.NoError(t, err, "Error generating key")

	channel, err := NewSecureChannel(key)
	assert.NoError(t, err, "Error creating secure channel")

	plaintext := []byte("test message")
	ciphertext, err := channel.Encrypt(plaintext)
	assert.NoError(t, err, "Error encrypting data")

	decryptedText, err := channel.Decrypt(ciphertext)
	assert.NoError(t, err, "Error decrypting data")

	assert.Equal(t, plaintext, decryptedText, "Decrypted text should match plaintext")
}

// TestArgon2KeyDerivation tests the Argon2 key derivation function
func TestArgon2KeyDerivation(t *testing.T) {
	password := []byte("test-password")
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	assert.NoError(t, err, "Error generating salt")

	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	assert.NotNil(t, key, "Derived key should not be nil")
	assert.Equal(t, 32, len(key), "Derived key length should be 32 bytes")
}

// TestScryptKeyDerivation tests the Scrypt key derivation function
func TestScryptKeyDerivation(t *testing.T) {
	password := []byte("test-password")
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	assert.NoError(t, err, "Error generating salt")

	key, err := scrypt.Key(password, salt, 16384, 8, 1, 32)
	assert.NoError(t, err, "Error deriving key using Scrypt")
	assert.NotNil(t, key, "Derived key should not be nil")
	assert.Equal(t, 32, len(key), "Derived key length should be 32 bytes")
}
