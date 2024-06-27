package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"synthron-blockchain/pkg/synnergy_network/core/common"
)

// Function to create a new block
func CreateBlock(transactions []*common.Transaction, prevBlockHash string) *common.Block {
	block := &common.Block{
		Timestamp:     time.Now().Unix(),
		Transactions:  transactions,
		PrevBlockHash: prevBlockHash,
	}

	block.Hash = CalculateHash(block)
	return block
}

// Function to calculate the hash of a block
func CalculateHash(block *common.Block) string {
	record := fmt.Sprintf("%d%s%d", block.Timestamp, block.PrevBlockHash, block.Nonce)
	hash := sha256.New()
	hash.Write([]byte(record))
	hashed := hash.Sum(nil)
	return hex.EncodeToString(hashed)
}

// Function to validate a block
func ValidateBlock(block *common.Block, difficulty int) bool {
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(block.Hash, prefix)
}

// AddBlock adds a new block to the blockchain after performing necessary validations.
func (bc *common.Blockchain) AddBlock(block *common.Block) error {
	if len(bc.Blocks) > 0 {
		block.PrevBlockHash = bc.Blocks[len(bc.Blocks)-1].Hash
	}

	block.Hash = CalculateHash(block)
	if !ValidateBlock(block, bc.Difficulty) {
		return errors.New("invalid proof of work")
	}

	bc.Blocks = append(bc.Blocks, block)
	return nil
}

// MineBlock performs the proof of work algorithm to mine a new block.
func (bc *common.Blockchain) MineBlock(transactions []*common.Transaction) (*common.Block, error) {
	var newBlock *common.Block
	nonce := 0

	for {
		newBlock = &common.Block{
			Timestamp:    time.Now().Unix(),
			Transactions: transactions,
			PrevBlockHash: bc.Blocks[len(bc.Blocks)-1].Hash,
			Nonce:        nonce,
		}
		newBlock.Hash = CalculateHash(newBlock)

		if ValidateBlock(newBlock, bc.Difficulty) {
			break
		}

		nonce++
	}

	if err := bc.AddBlock(newBlock); err != nil {
		return nil, err
	}

	return newBlock, nil
}
