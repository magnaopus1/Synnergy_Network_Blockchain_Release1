package custom_consensus

import (
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
)

// TestCreateBlock tests the CreateBlock function to ensure it adheres to the consensus rules and creates blocks correctly.
func TestCreateBlock(t *testing.T) {
    previousBlock := ConsensusBlock{
        PreviousHash: "0000000000abcdef",
        Transactions: []string{"tx1", "tx2"},
        Timestamp:    time.Now(),
        Nonce:        12345,
    }

    blockData := BlockData{
        Transactions: []string{"tx3", "tx4", "tx5"},
        TimeCreated:  time.Now(),
    }

    rule := ConsensusRule{
        MinTransaction:  3,
        BlockSizeLimit:  1000,
        BlockTimeInterval: 10 * time.Second,
    }

    newBlock, err := CreateBlock(previousBlock, blockData, rule)
    assert.NoError(t, err)
    assert.NotNil(t, newBlock)
    assert.Len(t, newBlock.Transactions, 3, "Block should contain exactly 3 transactions")
    assert.NotEmpty(t, newBlock.PreviousHash, "Previous hash should not be empty")
    assert.NotEqual(t, previousBlock.Nonce, newBlock.Nonce, "Nonce should be updated")
}

// TestFindValidNonce tests whether the findValidNonce function can find a nonce that meets the hash requirements under the given rules.
func TestFindValidNonce(t *testing.T) {
    block := ConsensusBlock{
        PreviousHash: "abcdef1234567890",
        Transactions: []string{"tx1", "tx2"},
        Timestamp:    time.Now(),
    }

    rule := ConsensusRule{
        MinTransaction:  2,
        BlockSizeLimit:  1000,
        BlockTimeInterval: 10 * time.Second,
    }

    nonce, err := findValidNonce(block, rule)
    assert.NoError(t, err)
    assert.True(t, isValidHash(calculateHash(block), rule.BlockSizeLimit), "Valid nonce should create a valid hash")
    assert.Greater(t, nonce, 0, "Nonce should be a positive number")
}

// TestEncryptData tests the encryption logic to ensure data is encrypted correctly using the specified algorithms.
func TestEncryptData(t *testing.T) {
    originalData := []byte("test data")
    key := []byte("verysecurekey123")

    encryptedData, err := EncryptData(originalData, key)
    assert.NoError(t, err)
    assert.NotEqual(t, originalData, encryptedData, "Encrypted data should not match the original")

    decryptedData, err := DecryptData(encryptedData, key)
    assert.NoError(t, err)
    assert.Equal(t, originalData, decryptedData, "Decrypted data should match the original")
}

// Add more test cases as required to cover all functionalities and edge cases.

