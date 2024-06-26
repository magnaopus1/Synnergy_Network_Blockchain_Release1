package financialinstitutions

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestProcessTransaction tests the encryption and storage logic for transactions.
func TestProcessTransaction(t *testing.T) {
	tl := NewTransactionLayer(generateRandomKey())

	// Create a sample transaction
	tx := Transaction{
		ID:       "tx1234",
		Amount:   100.00,
		Currency: "USD",
		Sender:   "sender_wallet_address",
		Receiver: "receiver_wallet_address",
	}

	// Process the transaction
	txID, err := tl.ProcessTransaction(tx)
	assert.Nil(t, err, "processing the transaction should not produce an error")
	assert.Equal(t, "tx1234", txID, "the transaction ID should match the input")

	// Verify that the transaction data is encrypted
	assert.NotEmpty(t, tx.SecureHash, "secure hash should not be empty after processing")
}

// TestValidateTransaction tests the validation logic to ensure it correctly verifies transaction integrity.
func TestValidateTransaction(t *testing.T) {
	tl := NewTransactionLayer(generateRandomKey())

	// Create and process a transaction
	tx := Transaction{
		ID:       "tx1234",
		Amount:   100.00,
		Currency: "USD",
		Sender:   "sender_wallet_address",
		Receiver: "receiver_wallet_address",
	}
	_, _ = tl.ProcessTransaction(tx)

	// Validate the transaction
	valid, err := tl.ValidateTransaction(tx)
	assert.Nil(t, err, "validation should not produce an error")
	assert.True(t, valid, "transaction should be valid")

	// Manipulate the transaction to test validation failure
	tx.Amount = 200.00
	valid, err = tl.ValidateTransaction(tx)
	assert.False(t, valid, "transaction should be invalid after manipulation")
}

// generateRandomKey generates a random 256-bit key for encryption.
func generateRandomKey() []byte {
	key := make([]byte, 32) // 256 bits for AES-256
	_, err := rand.Read(key)
	if err != nil {
		panic("failed to generate a random key")
	}
	return key
}

func TestMain(m *testing.M) {
	// Setup and teardown, if necessary
	m.Run()
}
