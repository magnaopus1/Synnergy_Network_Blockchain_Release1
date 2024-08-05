package interoperability

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
	"github.com/ethereum/go-ethereum/common"
)

// CrossChainBridge represents a bridge for transferring assets between different blockchains
type CrossChainBridge struct {
	ID              common.Hash
	Name            string
	SourceChain     string
	DestinationChain string
	BridgeAddress   common.Address
	BridgeFee       *big.Int
	Lock            sync.Mutex
	PendingTransfers map[common.Hash]*TransferRequest
	CompletedTransfers map[common.Hash]*TransferRequest
}

// TransferRequest represents a request to transfer assets across chains
type TransferRequest struct {
	ID              common.Hash
	FromAddress     common.Address
	ToAddress       common.Address
	Amount          *big.Int
	Nonce           *big.Int
	Timestamp       time.Time
	Signature       string
	Completed       bool
}

// NewCrossChainBridge initializes a new cross-chain bridge
func NewCrossChainBridge(name, sourceChain, destinationChain string, bridgeAddress common.Address, bridgeFee *big.Int) *CrossChainBridge {
	return &CrossChainBridge{
		ID:              generateBridgeID(name, sourceChain, destinationChain),
		Name:            name,
		SourceChain:     sourceChain,
		DestinationChain: destinationChain,
		BridgeAddress:   bridgeAddress,
		BridgeFee:       bridgeFee,
		PendingTransfers: make(map[common.Hash]*TransferRequest),
		CompletedTransfers: make(map[common.Hash]*TransferRequest),
	}
}

// RequestTransfer initiates a transfer request across chains
func (b *CrossChainBridge) RequestTransfer(fromAddress, toAddress common.Address, amount *big.Int) (*TransferRequest, error) {
	b.Lock.Lock()
	defer b.Lock.Unlock()

	if amount.Cmp(b.BridgeFee) < 0 {
		return nil, errors.New("amount is less than the bridge fee")
	}

	nonce := big.NewInt(time.Now().UnixNano())
	transferID := generateTransferID(fromAddress, toAddress, amount, nonce)
	timestamp := time.Now()
	signature, err := generateSignature(transferID, nonce)
	if err != nil {
		return nil, err
	}

	transferRequest := &TransferRequest{
		ID:            transferID,
		FromAddress:   fromAddress,
		ToAddress:     toAddress,
		Amount:        amount,
		Nonce:         nonce,
		Timestamp:     timestamp,
		Signature:     signature,
		Completed:     false,
	}

	b.PendingTransfers[transferID] = transferRequest
	return transferRequest, nil
}

// CompleteTransfer marks a transfer as completed
func (b *CrossChainBridge) CompleteTransfer(transferID common.Hash) error {
	b.Lock.Lock()
	defer b.Lock.Unlock()

	transfer, exists := b.PendingTransfers[transferID]
	if !exists {
		return errors.New("transfer request not found")
	}

	transfer.Completed = true
	b.CompletedTransfers[transferID] = transfer
	delete(b.PendingTransfers, transferID)

	return nil
}

// GetTransferStatus retrieves the status of a transfer request
func (b *CrossChainBridge) GetTransferStatus(transferID common.Hash) (*TransferRequest, error) {
	b.Lock.Lock()
	defer b.Lock.Unlock()

	if transfer, exists := b.CompletedTransfers[transferID]; exists {
		return transfer, nil
	}
	if transfer, exists := b.PendingTransfers[transferID]; exists {
		return transfer, nil
	}

	return nil, errors.New("transfer request not found")
}

// generateBridgeID generates a unique ID for the cross-chain bridge
func generateBridgeID(name, sourceChain, destinationChain string) common.Hash {
	data := fmt.Sprintf("%s:%s:%s", name, sourceChain, destinationChain)
	hash := sha256.Sum256([]byte(data))
	return common.BytesToHash(hash[:])
}

// generateTransferID generates a unique ID for a transfer request
func generateTransferID(fromAddress, toAddress common.Address, amount, nonce *big.Int) common.Hash {
	data := fmt.Sprintf("%s:%s:%s:%s", fromAddress.Hex(), toAddress.Hex(), amount.String(), nonce.String())
	hash := sha256.Sum256([]byte(data))
	return common.BytesToHash(hash[:])
}

// generateSignature generates a signature for a transfer request using Scrypt
func generateSignature(transferID common.Hash, nonce *big.Int) (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key(transferID.Bytes(), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}

	signature := hex.EncodeToString(key)
	return signature, nil
}
