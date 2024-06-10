package timestamping

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"synthron_blockchain/pkg/layer0/core/chain"
	"synthron_blockchain/pkg/layer0/core/crypto"
)

// VerificationManager handles the verification of timestamps and associated data within the blockchain.
type VerificationManager struct {
	Blockchain *chain.Blockchain
}

// NewVerificationManager initializes a new VerificationManager with a reference to the blockchain.
func NewVerificationManager(blockchain *chain.Blockchain) *VerificationManager {
	return &VerificationManager{
		Blockchain: blockchain,
	}
}

// VerifyDataIntegrity checks the integrity and authenticity of the data by comparing it against the stored hash.
func (vm *VerificationManager) VerifyDataIntegrity(data []byte, txID string) (bool, error) {
	hashed := sha256.Sum256(data)
	hashString := hex.EncodeToString(hashed[:])

	tx, err := vm.Blockchain.GetTransactionByID(txID)
	if err != nil {
		return false, fmt.Errorf("transaction retrieval failed: %v", err)
	}

	// Check if the hash stored in the transaction matches the computed hash
	if tx.Payload != hashString {
		return false, fmt.Errorf("data integrity check failed: hashes do not match")
	}

	return true, nil
}

// VerifyTimestamp uses the blockchain's consensus mechanism to validate the timestamp and associated data.
func (vm *ParsingUtility) VerifyTimestamp(txID string) (bool, error) {
	// Retrieve the transaction from the blockchain
	tx, err := vm.Blockchain.GetTransactionByID(txID)
	if err != nil {
		return false, fmt.Errorf("failed to retrieve transaction: %v", err)
	}

	// Check the transaction type and perform consensus checks
	if tx.Type != "TIMESTAMP" || !vm.Blockchain.ValidateTransaction(tx) {
		return false, fmt.Errorf("timestamp verification failed: invalid transaction type or consensus failure")
	}

	return true, nil
}

// SecureVerify uses cryptographic proofs, like Zero-Knowledge Proofs or homomorphic encryption, to enhance verification without compromising privacy.
func (vm *VerificationManager) SecureVerify(txID string, proof []byte) (bool, error) {
	// This function assumes a ZKP or homomorphic verification mechanism
	// For example, using zk-SNARKs to validate the transaction without revealing the underlying data
	valid, err := crypto.VerifyZKProof(proof)
	if err != nil || !valid {
		return false, fmt.Errorf("secure verification failed: %v", err)
	}

	return true, nil
}
