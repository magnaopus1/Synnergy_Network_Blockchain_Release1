package proof_of_history

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNewPoHGenerator tests the initialization of a new PoHGenerator.
func TestNewPoHGenerator(t *testing.T) {
	initialTransaction := "genesis"
	pohGenerator := NewPoHGenerator(initialTransaction)

	assert.NotNil(t, pohGenerator, "PoHGenerator should not be nil")
	assert.Equal(t, initialTransaction, pohGenerator.lastRecord.Transaction, "Initial transaction should match the genesis transaction")
	assert.NotEmpty(t, pohGenerator.lastRecord.Hash, "Initial hash should not be empty")
}

// TestCreateRecord tests the functionality to create new historical records.
func TestCreateRecord(t *testing.T) {
	pohGenerator := NewPoHGenerator("genesis")
	newTransaction := "new transaction"
	record := pohGenerator.CreateRecord(newTransaction)

	assert.NotNil(t, record, "The new record should not be nil")
	assert.Equal(t, newTransaction, record.Transaction, "Record transaction should match the new transaction")
	assert.NotEmpty(t, record.Hash, "Record hash should not be empty")
	assert.Equal(t, pohGenerator.lastRecord, record, "The last record should be the newly created record")
}

// TestVerifyRecord tests the verification process of historical records.
func TestVerifyRecord(t *testing.T) {
	pohGenerator := NewPoHGenerator("genesis")
	record := pohGenerator.CreateRecord("transaction 1")
	assert.True(t, pohGenerator.VerifyRecord(record), "The record should be valid")

	// Tamper with the record
	record.Transaction = "tampered transaction"
	assert.False(t, pohGenerator.VerifyRecord(record), "The record should be invalid after tampering")
}

// TestEncryptAndDecryptRecords tests the encryption and decryption of PoH records.
func TestEncryptAndDecryptRecords(t *testing.T) {
	key := []byte("verysecretkey0123456789")
	pohGenerator := NewPoHGenerator("genesis")
	pohGenerator.CreateRecord("transaction 1")
	pohGenerator.CreateRecord("transaction 2")

	// Encrypt policies
	encryptedData, err := pohGenerator.EncryptPolicies()
	assert.Nil(t, err, "Encryption should not error")
	assert.NotEmpty(t, encryptedData, "Encrypted data should not be empty")

	// Decrypt policies
	err = pohGenerator.DecryptPolicies(encryptedData)
	assert.Nil(t, err, "Decryption should not error")

	// Verify data integrity
	lastRecord := pohGenerator.RetrieveLastRecord()
	assert.Equal(t, "transaction 2", lastRecord.Transaction, "Decrypted transaction should match the original data")
}

// Run all tests
func TestAll(t *testing.T) {
	t.Run("TestNewPoHGenerator", TestNewPoHGenerator)
	t.Run("TestCreateRecord", TestCreateRecord)
	t.Run("TestVerifyRecord", TestVerifyRecord)
	t.Run("TestEncryptAndDecryptRecords", TestEncryptAndDecryptRecords)
}
