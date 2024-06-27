package consensus

import (
	"crypto"
	"fmt"

	"synnergy_network/pkg/synnergy_network/core/common"
	"github.com/cisco/go-quantumresistant"
)

// QuantumResistantPoH extends PoH to include quantum-resistant cryptographic techniques.
type QuantumResistantPoH struct {
	*PoH
	QuantumResistantCrypto *quantumresistant.QuantumResistantCrypto
}

// NewQuantumResistantPoH initializes a new PoH with quantum-resistant features.
func NewQuantumResistantPoH() *QuantumResistantPoH {
	return &QuantumResistantPoH{
		PoH:                    NewPoH(),
		QuantumResistantCrypto: quantumresistant.NewQuantumResistantCrypto(),
	}
}

// GenerateQuantumResistantHash generates a hash using a quantum-resistant algorithm.
func (qrp *QuantumResistantPoH) GenerateQuantumResistantHash(data []byte) (string, error) {
	hash, err := qrp.QuantumResistantCrypto.Hash(data)
	if err != nil {
		return "", fmt.Errorf("quantum-resistant hashing failed: %v", err)
	}
	return hash, nil
}

// SignTransaction signs a transaction using a quantum-resistant digital signature.
func (qrp *QuantumResistantPoH) SignTransaction(tx *common.Transaction) (string, error) {
	signature, err := qrp.QuantumResistantCrypto.Sign(tx.Serialize(), crypto.Hash(0))
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction with quantum-resistant signature: %v", err)
	}
	return signature, nil
}

// VerifyQuantumResistantSignature verifies a digital signature against the given transaction.
func (qrp *QuantumResistantPoH) VerifyQuantumResistantSignature(signature string, tx *common.Transaction) bool {
	return qrp.QuantumResistantCrypto.Verify(tx.Serialize(), signature, crypto.Hash(0))
}

// AppendQuantumResistantBlock adds a new block to the blockchain with quantum-resistant properties.
func (qrp *QuantumResistantPoH) AppendQuantumResistantBlock(block *Block) error {
	if err := qrp.VerifyBlock(block); err != nil {
		return err
	}
	return qrp.PoH.AppendBlock(block)
}

// VerifyBlock extends block verification with quantum-resistant validation.
func (qrp *QuantumResistantPoH) VerifyBlock(block *Block) error {
	if !qrp.VerifyQuantumResistantSignature(block.Signature, &block.Transaction) {
		return fmt.Errorf("invalid quantum-resistant signature")
	}
	return nil
}

