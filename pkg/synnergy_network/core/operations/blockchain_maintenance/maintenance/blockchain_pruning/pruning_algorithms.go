package blockchain_pruning

import (
	"log"
	"time"
	"sync"
	"github.com/synnergy_network/utils/encryption_utils"
	"github.com/synnergy_network/utils/logging_utils"
)

// Blockchain represents the structure of the blockchain
type Blockchain struct {
	Blocks []Block
	mu     sync.Mutex
}

// Block represents the structure of a block in the blockchain
type Block struct {
	Index        int
	Timestamp    time.Time
	Data         string
	PreviousHash string
	Hash         string
}

// PruningConfig holds the configuration for pruning
type PruningConfig struct {
	MaxBlocks int // Maximum number of blocks to retain
}

// PruningAlgorithms provides various methods for pruning the blockchain
type PruningAlgorithms struct {
	blockchain   *Blockchain
	pruningConfig PruningConfig
	logger       *logging_utils.Logger
}

// NewPruningAlgorithms creates a new instance of PruningAlgorithms
func NewPruningAlgorithms(blockchain *Blockchain, pruningConfig PruningConfig, logger *logging_utils.Logger) *PruningAlgorithms {
	return &PruningAlgorithms{
		blockchain:   blockchain,
		pruningConfig: pruningConfig,
		logger:       logger,
	}
}

// Prune removes unnecessary data from the blockchain while preserving integrity
func (pa *PruningAlgorithms) Prune() {
	pa.blockchain.mu.Lock()
	defer pa.blockchain.mu.Unlock()

	if len(pa.blockchain.Blocks) > pa.pruningConfig.MaxBlocks {
		pruneIndex := len(pa.blockchain.Blocks) - pa.pruningConfig.MaxBlocks
		pa.blockchain.Blocks = pa.blockchain.Blocks[pruneIndex:]
		pa.logger.Info("Blockchain pruned to retain maximum of %d blocks", pa.pruningConfig.MaxBlocks)
	} else {
		pa.logger.Info("No pruning necessary. Current block count is within the limit.")
	}
}

// AdaptivePruning dynamically adjusts the pruning strategy based on network conditions
func (pa *PruningAlgorithms) AdaptivePruning(networkLoad int) {
	pa.blockchain.mu.Lock()
	defer pa.blockchain.mu.Unlock()

	var adjustedMaxBlocks int
	if networkLoad > 75 {
		adjustedMaxBlocks = pa.pruningConfig.MaxBlocks / 2
	} else if networkLoad < 25 {
		adjustedMaxBlocks = pa.pruningConfig.MaxBlocks * 2
	} else {
		adjustedMaxBlocks = pa.pruningConfig.MaxBlocks
	}

	if len(pa.blockchain.Blocks) > adjustedMaxBlocks {
		pruneIndex := len(pa.blockchain.Blocks) - adjustedMaxBlocks
		pa.blockchain.Blocks = pa.blockchain.Blocks[pruneIndex:]
		pa.logger.Info("Adaptive pruning applied. Blockchain pruned to retain maximum of %d blocks", adjustedMaxBlocks)
	} else {
		pa.logger.Info("No adaptive pruning necessary. Current block count is within the limit.")
	}
}

// ConsistencyCheck ensures the integrity of the blockchain after pruning
func (pa *PruningAlgorithms) ConsistencyCheck() bool {
	pa.blockchain.mu.Lock()
	defer pa.blockchain.mu.Unlock()

	for i := 1; i < len(pa.blockchain.Blocks); i++ {
		if pa.blockchain.Blocks[i].PreviousHash != pa.blockchain.Blocks[i-1].Hash {
			pa.logger.Error("Inconsistency detected between blocks %d and %d", i-1, i)
			return false
		}
	}
	pa.logger.Info("Blockchain consistency check passed.")
	return true
}

// EncryptBlockData encrypts the data of a specific block using AES encryption
func (pa *PruningAlgorithms) EncryptBlockData(blockIndex int, key string) error {
	pa.blockchain.mu.Lock()
	defer pa.blockchain.mu.Unlock()

	if blockIndex < 0 || blockIndex >= len(pa.blockchain.Blocks) {
		return fmt.Errorf("invalid block index")
	}

	block := &pa.blockchain.Blocks[blockIndex]
	encryptedData, err := encryption_utils.EncryptAES(block.Data, key)
	if err != nil {
		pa.logger.Error("Error encrypting block data: %v", err)
		return err
	}

	block.Data = encryptedData
	pa.logger.Info("Block data at index %d encrypted successfully", blockIndex)
	return nil
}

// DecryptBlockData decrypts the data of a specific block using AES decryption
func (pa *PruningAlgorithms) DecryptBlockData(blockIndex int, key string) error {
	pa.blockchain.mu.Lock()
	defer pa.blockchain.mu.Unlock()

	if blockIndex < 0 || blockIndex >= len(pa.blockchain.Blocks) {
		return fmt.Errorf("invalid block index")
	}

	block := &pa.blockchain.Blocks[blockIndex]
	decryptedData, err := encryption_utils.DecryptAES(block.Data, key)
	if err != nil {
		pa.logger.Error("Error decrypting block data: %v", err)
		return err
	}

	block.Data = decryptedData
	pa.logger.Info("Block data at index %d decrypted successfully", blockIndex)
	return nil
}
