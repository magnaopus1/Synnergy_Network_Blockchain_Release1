package blockchain_qkd

import (
	"testing"
	"time"
	"github.com/stretchr/testify/assert"
)

// TestAddEntry tests adding entries to the ledger and blockchain
func TestAddEntry(t *testing.T) {
	ledger := NewImmutableLedger(3)

	entry1 := LedgerEntry{
		KeyID:     "key1",
		Timestamp: time.Now(),
		Action:    "add",
		Key:       "exampleQuantumKey1",
	}
	err := ledger.AddEntry(entry1)
	assert.NoError(t, err, "Error should be nil when adding a valid entry")

	entry2 := LedgerEntry{
		KeyID:     "key1",
		Timestamp: time.Now(),
		Action:    "add",
		Key:       "exampleQuantumKey2",
	}
	err = ledger.AddEntry(entry2)
	assert.Error(t, err, "Error should be returned when adding an entry with duplicate KeyID")

	entry3 := LedgerEntry{
		KeyID:     "key2",
		Timestamp: time.Now(),
		Action:    "revoke",
		Key:       "exampleQuantumKey2",
	}
	err = ledger.AddEntry(entry3)
	assert.Error(t, err, "Error should be returned when revoking a non-existent key")
}

// TestCreateBlock tests the creation of a new block in the blockchain
func TestCreateBlock(t *testing.T) {
	ledger := NewImmutableLedger(2)

	entry1 := LedgerEntry{
		KeyID:     "key1",
		Timestamp: time.Now(),
		Action:    "add",
		Key:       "exampleQuantumKey1",
	}
	ledger.AddEntry(entry1)

	entry2 := LedgerEntry{
		KeyID:     "key2",
		Timestamp: time.Now(),
		Action:    "add",
		Key:       "exampleQuantumKey2",
	}
	ledger.AddEntry(entry2)

	assert.Equal(t, 1, len(ledger.blockchain), "Blockchain should have one block after reaching block size")
	assert.Equal(t, 0, len(ledger.transactionPool), "Transaction pool should be empty after block creation")
}

// TestValidateBlockchain tests the validation of the blockchain integrity
func TestValidateBlockchain(t *testing.T) {
	ledger := NewImmutableLedger(2)

	entry1 := LedgerEntry{
		KeyID:     "key1",
		Timestamp: time.Now(),
		Action:    "add",
		Key:       "exampleQuantumKey1",
	}
	ledger.AddEntry(entry1)

	entry2 := LedgerEntry{
		KeyID:     "key2",
		Timestamp: time.Now(),
		Action:    "add",
		Key:       "exampleQuantumKey2",
	}
	ledger.AddEntry(entry2)

	entry3 := LedgerEntry{
		KeyID:     "key3",
		Timestamp: time.Now(),
		Action:    "add",
		Key:       "exampleQuantumKey3",
	}
	ledger.AddEntry(entry3)

	err := ledger.ValidateBlockchain()
	assert.NoError(t, err, "Blockchain should validate successfully")

	// Tampering with the blockchain
	ledger.blockchain[0].Transactions[0].Key = "tamperedKey"
	err = ledger.ValidateBlockchain()
	assert.Error(t, err, "Blockchain validation should fail if data is tampered")
}

// TestQuantumKeyDistribution tests the quantum key distribution lifecycle
func TestQuantumKeyDistribution(t *testing.T) {
	ledger := NewImmutableLedger(3)
	km := NewKeyManager(24 * time.Hour)

	// Generate and distribute a new quantum-resistant key
	keyID := "exampleKeyID"
	key, err := km.GenerateQuantumKey(keyID)
	assert.NoError(t, err, "Quantum key generation should succeed")

	entry := LedgerEntry{
		KeyID:     keyID,
		Timestamp: time.Now(),
		Action:    "add",
		Key:       key,
	}
	err = ledger.AddEntry(entry)
	assert.NoError(t, err, "Adding quantum key entry should succeed")

	// Revoke the key
	err = km.RevokeKey(keyID)
	assert.NoError(t, err, "Quantum key revocation should succeed")

	entry = LedgerEntry{
		KeyID:     keyID,
		Timestamp: time.Now(),
		Action:    "revoke",
		Key:       key,
	}
	err = ledger.AddEntry(entry)
	assert.NoError(t, err, "Adding revocation entry should succeed")

	// Validate the blockchain
	err = ledger.ValidateBlockchain()
	assert.NoError(t, err, "Blockchain should validate successfully after key revocation")
}

// TestIntegrityVerification tests the integrity verification of quantum key exchanges
func TestIntegrityVerification(t *testing.T) {
	ledger := NewImmutableLedger(3)

	entry := LedgerEntry{
		KeyID:     "key1",
		Timestamp: time.Now(),
		Action:    "add",
		Key:       "exampleQuantumKey1",
	}
	ledger.AddEntry(entry)

	hash := ledger.calculateHash(ledger.blockchain[0])
	assert.Equal(t, ledger.blockchain[0].Hash, hash, "Hash should match the calculated hash for the block")

	// Tampering with the ledger
	ledger.blockchain[0].Transactions[0].Key = "tamperedKey"
	hash = ledger.calculateHash(ledger.blockchain[0])
	assert.NotEqual(t, ledger.blockchain[0].Hash, hash, "Hash should not match after tampering with the block")
}
