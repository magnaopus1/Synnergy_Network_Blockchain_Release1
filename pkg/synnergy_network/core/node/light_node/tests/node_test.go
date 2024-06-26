package lightnode

import (
    "crypto/sha256"
    "encoding/hex"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
)

// Mock data for testing
var mockBlockHeader = BlockHeader{
    Height:    1,
    PrevHash:  "0x123",
    Timestamp: time.Now().Unix(),
    Hash:      "0x456",
}

var mockTransaction = Transaction{
    ID:     "tx123",
    Amount: 100,
    From:   "Alice",
    To:     "Bob",
    Data:   "Payment for services",
}

var mockMerkleProof = MerkleProof{
    Transactions: []string{"tx123"},
    Hashes:       []string{"0x789"},
}

// Test functions

// Test for validating a block header
func TestValidateBlockHeader(t *testing.T) {
    header := mockBlockHeader
    headerData := []byte(header.PrevHash + string(header.Height) + string(header.Timestamp))
    hash := sha256.Sum256(headerData)
    header.Hash = hex.EncodeToString(hash[:])

    valid := validateBlockHeader(header)
    assert.True(t, valid, "Block header validation failed")
}

// Test for verifying a transaction using Merkle proof
func TestVerifyTransaction(t *testing.T) {
    tx := mockTransaction
    proof := mockMerkleProof

    valid := verifyTransaction(tx, proof)
    assert.True(t, valid, "Transaction verification failed")
}

// Test for fetching block header from a trusted full node
func TestFetchBlockHeader(t *testing.T) {
    // Mocking the fetch function
    fetchBlockHeader = func(height int) (BlockHeader, error) {
        return mockBlockHeader, nil
    }

    header, err := fetchBlockHeader(1)
    assert.NoError(t, err, "Error fetching block header")
    assert.Equal(t, mockBlockHeader, header, "Fetched block header does not match")
}

// Test for syncing block headers
func TestSyncBlockHeaders(t *testing.T) {
    // Mocking the fetch function
    fetchBlockHeader = func(height int) (BlockHeader, error) {
        return mockBlockHeader, nil
    }

    headers, err := syncBlockHeaders(1, 10)
    assert.NoError(t, err, "Error syncing block headers")
    assert.Equal(t, 10, len(headers), "Number of synced block headers does not match")
}

// Test for handling intermittent connectivity
func TestIntermittentConnectivity(t *testing.T) {
    // Simulate intermittent connectivity by delaying fetch operations
    fetchBlockHeader = func(height int) (BlockHeader, error) {
        time.Sleep(2 * time.Second)
        return mockBlockHeader, nil
    }

    start := time.Now()
    _, err := syncBlockHeaders(1, 5)
    duration := time.Since(start)

    assert.NoError(t, err, "Error during intermittent connectivity test")
    assert.True(t, duration.Seconds() >= 10, "Intermittent connectivity handling failed")
}

// Helper functions

func validateBlockHeader(header BlockHeader) bool {
    headerData := []byte(header.PrevHash + string(header.Height) + string(header.Timestamp))
    hash := sha256.Sum256(headerData)
    return header.Hash == hex.EncodeToString(hash[:])
}

func verifyTransaction(tx Transaction, proof MerkleProof) bool {
    txData := []byte(tx.ID + tx.From + tx.To + string(tx.Amount) + tx.Data)
    hash := sha256.Sum256(txData)
    return proof.Hashes[0] == hex.EncodeToString(hash[:])
}

func fetchBlockHeader(height int) (BlockHeader, error) {
    // Mock implementation, should be replaced with actual network call
    return mockBlockHeader, nil
}

func syncBlockHeaders(startHeight, endHeight int) ([]BlockHeader, error) {
    var headers []BlockHeader
    for i := startHeight; i <= endHeight; i++ {
        header, err := fetchBlockHeader(i)
        if err != nil {
            return nil, err
        }
        headers = append(headers, header)
    }
    return headers, nil
}
