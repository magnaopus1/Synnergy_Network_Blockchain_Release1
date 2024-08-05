package transactions

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn722/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn722/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn722/storage"
)

// BatchTransfer struct handles batch transfers of SYN722 tokens
type BatchTransfer struct {
	ledger  *ledger.Ledger
	storage *storage.Storage
	mutex   sync.Mutex
}

// NewBatchTransfer initializes and returns a new BatchTransfer instance
func NewBatchTransfer(ledger *ledger.Ledger, storage *storage.Storage) *BatchTransfer {
	return &BatchTransfer{
		ledger:  ledger,
		storage: storage,
	}
}

// TransferRequest struct defines the structure of a transfer request
type TransferRequest struct {
	From      string            `json:"from"`
	To        string            `json:"to"`
	TokenID   string            `json:"token_id"`
	Amount    float64           `json:"amount,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Signature string            `json:"signature"`
}

// BatchTransferRequest struct defines the structure of a batch transfer request
type BatchTransferRequest struct {
	Transfers []TransferRequest `json:"transfers"`
}

// ValidateTransfer validates a single transfer request
func (bt *BatchTransfer) ValidateTransfer(req TransferRequest) error {
	// Verify signature
	if !security.VerifySignature(req.From, req.Signature, req.TokenID+req.To) {
		return errors.New("invalid signature")
	}

	// Check if the token exists
	token, err := bt.ledger.GetToken(req.TokenID)
	if err != nil {
		return err
	}

	// Check if the sender has enough balance or ownership
	if token.Mode == "fungible" {
		balance, err := bt.ledger.GetBalance(req.From, req.TokenID)
		if err != nil || balance < req.Amount {
			return errors.New("insufficient balance")
		}
	} else {
		owner, err := bt.ledger.GetOwner(req.TokenID)
		if err != nil || owner != req.From {
			return errors.New("not the owner of the token")
		}
	}

	return nil
}

// ProcessTransfer processes a single transfer request
func (bt *BatchTransfer) ProcessTransfer(req TransferRequest) error {
	bt.mutex.Lock()
	defer bt.mutex.Unlock()

	token, err := bt.ledger.GetToken(req.TokenID)
	if err != nil {
		return err
	}

	if token.Mode == "fungible" {
		if err := bt.ledger.TransferFungibleToken(req.From, req.To, req.TokenID, req.Amount); err != nil {
			return err
		}
	} else {
		if err := bt.ledger.TransferNonFungibleToken(req.From, req.To, req.TokenID); err != nil {
			return err
		}
	}

	// Update transaction history
	txRecord := map[string]interface{}{
		"from":      req.From,
		"to":        req.To,
		"token_id":  req.TokenID,
		"amount":    req.Amount,
		"metadata":  req.Metadata,
		"timestamp": security.GetCurrentTimestamp(),
	}
	return bt.storage.Put("tx_"+req.TokenID+"_"+security.GenerateUUID(), txRecord)
}

// ExecuteBatchTransfer validates and processes a batch transfer request
func (bt *BatchTransfer) ExecuteBatchTransfer(req BatchTransferRequest) error {
	for _, transfer := range req.Transfers {
		if err := bt.ValidateTransfer(transfer); err != nil {
			return err
		}
	}

	for _, transfer := range req.Transfers {
		if err := bt.ProcessTransfer(transfer); err != nil {
			return err
		}
	}

	return nil
}

// EncryptBatchTransferRequest encrypts a batch transfer request
func (bt *BatchTransfer) EncryptBatchTransferRequest(req BatchTransferRequest, passphrase string) (string, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	encryptedData, err := security.Encrypt([]byte(passphrase), data)
	if err != nil {
		return "", err
	}

	return string(encryptedData), nil
}

// DecryptBatchTransferRequest decrypts a batch transfer request
func (bt *BatchTransfer) DecryptBatchTransferRequest(encryptedReq string, passphrase string) (BatchTransferRequest, error) {
	encryptedData := []byte(encryptedReq)
	decryptedData, err := security.Decrypt([]byte(passphrase), encryptedData)
	if err != nil {
		return BatchTransferRequest{}, err
	}

	var req BatchTransferRequest
	if err := json.Unmarshal(decryptedData, &req); err != nil {
		return BatchTransferRequest{}, err
	}

	return req, nil
}

// LogBatchTransfer logs the details of a batch transfer
func (bt *BatchTransfer) LogBatchTransfer(req BatchTransferRequest) error {
	logRecord := map[string]interface{}{
		"transfers": req.Transfers,
		"timestamp": security.GetCurrentTimestamp(),
	}

	return bt.storage.Put("batch_tx_"+security.GenerateUUID(), logRecord)
}
