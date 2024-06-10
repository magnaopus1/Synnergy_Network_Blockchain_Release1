package replication

import (
	"context"
	"errors"
	"log"

	"synthron_blockchain/pkg/layer0/core/crypto"
	"synthron_blockchain/pkg/layer0/core/storage"
	"github.com/ipfs/go-ipfs-api"
)

// RecoveryManager handles the data recovery and redundancy across the blockchain network.
type RecoveryManager struct {
	storageClient *storage.Client
	ipfsShell     *shell.Shell
}

// NewRecoveryManager initializes a new recovery manager with dependencies.
func NewRecoveryManager(storageClient *storage.Client, ipfsHost string) *RecoveryManager {
	return &RecoveryManager{
		storageClient: storageClient,
		ipfsShell:     shell.NewShell(ipfsHost),
	}
}

// ReplicateData replicates given data across multiple storage nodes.
func (rm *RecoveryManager) ReplicateData(ctx context.Context, data []byte) error {
	// Generate a cryptographic hash for data integrity verification
	hash, err := crypto.GenerateHash(data)
	if err != nil {
		return err
	}

	// Store data on IPFS
	cid, err := rm.ipfsShell.Add(bytes.NewReader(data))
	if err != nil {
		return err
	}

	log.Printf("Data replicated with CID: %s and Hash: %x", cid, hash)
	return nil
}

// RestoreData retrieves data from IPFS using the given CID.
func (rm *RecoveryManager) RestoreData(ctx context.Context, cid string) ([]byte, error) {
	reader, err := rm.ipfsShell.Cat(cid)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// ValidateDataIntegrity checks the integrity of the data using its hash.
func (rm *RecoveryManager) ValidateDataIntegrity(originalHash []byte, data []byte) bool {
	currentHash, err := crypto.GenerateHash(data)
	if err != nil {
		log.Println("Failed to generate hash:", err)
		return false
	}

	return crypto.SecureCompare(originalHash, currentHash)
}

