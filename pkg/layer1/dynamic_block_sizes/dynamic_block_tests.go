package dynamicblocksizes

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDynamicBlockSizeAdjustment checks the adjustment logic of block sizes under different transaction volumes.
func TestDynamicBlockSizeAdjustment(t *testing.T) {
	minSize := 100 // Minimum block size in KB
	maxSize := 1000 // Maximum block size in KB
	adjustmentFactor := 0.05 // Adjustment factor for size calculation

	manager := NewBlockSizeManager(minSize, maxSize, adjustmentFactor)

	// Scenario: Low transaction volume
	lowTxCount := 100
	manager.AdjustBlockSize(lowTxCount)
	assert.Equal(t, minSize, manager.CurrentSize, "Block size should not decrease below minimum")

	// Scenario: High transaction volume
	highTxCount := 5000
	manager.AdjustBlockSize(highTxCount)
	assert.LessOrEqual(t, manager.CurrentSize, maxSize, "Block size should not exceed maximum")

	// Scenario: Medium transaction volume should adjust between min and max
	mediumTxCount := 1000
	manager.AdjustBlockSize(mediumTxCount)
	assert.Greater(t, manager.CurrentSize, minSize, "Block size should increase")
	assert.Less(t, manager.CurrentSize, maxSize, "Block size should not reach maximum")
}

// TestBlockSizeEncryption tests the encryption and decryption of the block size.
func TestBlockSizeEncryption(t *testing.T) {
	manager := NewBlockSizeManager(100, 1000, 0.05)
	key := make([]byte, 32) // AES-256 requires 32 bytes key
	_, err := rand.Read(key)
	assert.NoError(t, err, "Key generation should not fail")

	encryptedSize, err := manager.EncryptCurrentSize(key)
	assert.NoError(t, err, "Encryption should succeed")

	decryptedSize, err := DecryptSize(encryptedSize, key)
	assert.NoError(t, err, "Decryption should succeed")
	assert.Equal(t, manager.CurrentSize, decryptedSize, "Decrypted size should match the original")
}

// TestBlockSizeBoundaryConditions tests the block size at boundary conditions.
func TestBlockSizeBoundaryConditions(t *testing.T) {
	manager := NewBlockSizeManager(100, 1000, 0.05)

	// Test minimum boundary condition
	manager.AdjustBlockSize(0)
	assert.Equal(t, manager.MinSize, manager.CurrentSize, "Block size should be at minimum with zero transactions")

	// Test maximum boundary condition
	manager.AdjustBlockSize(10000)
	assert.Equal(t, manager.MaxSize, manager.CurrentSize, "Block size should be at maximum with high transactions")
}

