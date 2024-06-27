package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"synnergy_network/pkg/synnergy_network/core/common"
	"synnergy_network/pkg/synnergy_network/core/privacy"
)

// PrivacyEnhancedPoH extends PoH to include privacy mechanisms.
type PrivacyEnhancedPoH struct {
	*PoH
	privacyLayer *privacy.PrivacyService
}

// NewPrivacyEnhancedPoH creates a new privacy-enhanced Proof of History blockchain.
func NewPrivacyEnhancedPoH() *PrivacyEnhancedPoH {
	return &PrivacyEnhancedPoH{
		PoH:          NewPoH(),
		privacyLayer: privacy.NewPrivacyService(),
	}
}

// CreatePrivateBlock generates a new block where transaction details are selectively disclosed.
func (pep *PrivacyEnhancedPoH) CreatePrivateBlock(transactions []*privacy.PrivateTransaction, prevBlock *Block) (*Block, error) {
	if pep.privacyLayer == nil {
		return nil, errors.New("privacy layer not initialized")
	}

	// Encrypt and seal transaction data
	for _, tx := range transactions {
		if err := pep.privacyLayer.SealTransaction(tx); err != nil {
			return nil, fmt.Errorf("failed to seal transaction: %v", err)
		}
	}

	block := &Block{
		Timestamp:       common.GetCurrentTimestamp(),
		Transactions:    make([]Transaction, len(transactions)),
		PrevBlockHash:   prevBlock.ThisBlockHash,
		MerkleRoot:      CalculateMerkleRoot(transactions),
	}

	block.ThisBlockHash = GenerateHash(block)
	block.CryptographicAnchor = GenerateCryptographicAnchor(block)
	return block, nil
}

// AppendPrivateBlock appends a privacy-enhanced block to the blockchain.
func (pep *PrivacyEnhancedPoH) AppendPrivateBlock(block *Block) error {
	return pep.PoH.AppendBlock(block)
}

// DecryptTransactionDetails reveals the details of encrypted transactions for authorized users.
func (pep *PrivacyEnhancedPoH) DecryptTransactionDetails(tx *privacy.PrivateTransaction, userKey string) (interface{}, error) {
	return pep.privacyLayer.DecryptTransaction(tx, userKey)
}

// GeneratePrivacyProof generates a zero-knowledge proof to verify a transaction without revealing its contents.
func (pep *PrivacyEnhancedPoH) GeneratePrivacyProof(tx *privacy.PrivateTransaction) (string, error) {
	return pep.privacyLayer.GenerateProof(tx)
}

// ValidatePrivacyProof validates the zero-knowledge proof provided for a transaction.
func (pep *PrivacyEnhancedPoH) ValidatePrivacyProof(proof string, tx *privacy.PrivateTransaction) bool {
	return pep.privacyLayer.ValidateProof(proof, tx)
}

