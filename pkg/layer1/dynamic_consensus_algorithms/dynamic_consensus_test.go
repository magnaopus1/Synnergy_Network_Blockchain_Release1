package dynamicconsensus

import (
	"crypto/aes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdjustParameters(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // AES-256 requires 32 bytes key
	manager := NewConsensusManager(key)

	tests := []struct {
		name            string
		blockTime       time.Duration
		minerReward     float64
		transactionLimit int
		expectedError   bool
	}{
		{"Valid Adjustment", 15 * time.Second, 10.0, 2000, false},
		{"Invalid Block Time", -5 * time.Second, 10.0, 1000, true},
		{"Invalid Reward", 10 * time.Second, -5, 1000, true},
		{"Invalid Limit", 10 * time.Second, 10.0, -100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.AdjustParameters(tt.blockTime, tt.minerReward, tt.transactionLimit)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.blockTime, manager.params.BlockTime)
				assert.Equal(t, tt.minerReward, manager.params.MinerReward)
				assert.Equal(t, tt.transactionLimit, manager.params.TransactionLimit)
			}
		})
	}
}

func TestEncryptionDecryption(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	manager := NewConsensusManager(key)

	// Modify parameters and test encryption
	_ = manager.AdjustParameters(20*time.Second, 15.0, 1500)
	encrypted, err := manager.EncryptParameters()
	require.NoError(t, err, "Encryption should succeed")

	// Decrypt and verify correctness
	err = manager.DecryptParameters(encrypted)
	require.NoError(t, err, "Decryption should succeed")

	assert.Equal(t, 20*time.Second, manager.params.BlockTime, "BlockTime should match post decryption")
	assert.Equal(t, 15.0, manager.params.MinerReward, "MinerReward should match post decryption")
	assert.Equal(t, 1500, manager.params.TransactionLimit, "TransactionLimit should match post decryption")
}

// Add additional tests for LogParameters and other auxiliary functions as needed.
