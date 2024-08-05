package transactions

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn722/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn722/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn722/storage"
)

// DualModeSwitch struct handles the switching between fungible and non-fungible modes of SYN722 tokens
type DualModeSwitch struct {
	ledger  *ledger.Ledger
	storage *storage.Storage
	mutex   sync.Mutex
}

// NewDualModeSwitch initializes and returns a new DualModeSwitch instance
func NewDualModeSwitch(ledger *ledger.Ledger, storage *storage.Storage) *DualModeSwitch {
	return &DualModeSwitch{
		ledger:  ledger,
		storage: storage,
	}
}

// ModeSwitchRequest struct defines the structure of a mode switch request
type ModeSwitchRequest struct {
	TokenID   string `json:"token_id"`
	NewMode   string `json:"new_mode"`
	Condition string `json:"condition,omitempty"`
	Signature string `json:"signature"`
}

// ValidateModeSwitch validates a mode switch request
func (dms *DualModeSwitch) ValidateModeSwitch(req ModeSwitchRequest) error {
	// Verify signature
	if !security.VerifySignature(req.TokenID, req.Signature, req.NewMode+req.Condition) {
		return errors.New("invalid signature")
	}

	// Check if the token exists
	token, err := dms.ledger.GetToken(req.TokenID)
	if err != nil {
		return err
	}

	// Check if the new mode is valid
	if req.NewMode != "fungible" && req.NewMode != "non-fungible" {
		return errors.New("invalid mode")
	}

	// Check if the condition for the switch is met
	if req.Condition != "" {
		// Here you can add logic to validate the condition
		// For example, checking if a specific date is reached or an action is completed
	}

	return nil
}

// ProcessModeSwitch processes a mode switch request
func (dms *DualModeSwitch) ProcessModeSwitch(req ModeSwitchRequest) error {
	dms.mutex.Lock()
	defer dms.mutex.Unlock()

	token, err := dms.ledger.GetToken(req.TokenID)
	if err != nil {
		return err
	}

	// Update the mode of the token in the ledger
	if err := dms.ledger.UpdateTokenMode(req.TokenID, req.NewMode); err != nil {
		return err
	}

	// Log the mode switch event
	event := map[string]interface{}{
		"token_id":  req.TokenID,
		"new_mode":  req.NewMode,
		"condition": req.Condition,
		"timestamp": security.GetCurrentTimestamp(),
	}
	if err := dms.storage.Put("mode_switch_"+req.TokenID+"_"+security.GenerateUUID(), event); err != nil {
		return err
	}

	return nil
}

// ExecuteModeSwitch validates and processes a mode switch request
func (dms *DualModeSwitch) ExecuteModeSwitch(req ModeSwitchRequest) error {
	if err := dms.ValidateModeSwitch(req); err != nil {
		return err
	}
	return dms.ProcessModeSwitch(req)
}

// EncryptModeSwitchRequest encrypts a mode switch request
func (dms *DualModeSwitch) EncryptModeSwitchRequest(req ModeSwitchRequest, passphrase string) (string, error) {
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

// DecryptModeSwitchRequest decrypts a mode switch request
func (dms *DualModeSwitch) DecryptModeSwitchRequest(encryptedReq string, passphrase string) (ModeSwitchRequest, error) {
	encryptedData := []byte(encryptedReq)
	decryptedData, err := security.Decrypt([]byte(passphrase), encryptedData)
	if err != nil {
		return ModeSwitchRequest{}, err
	}

	var req ModeSwitchRequest
	if err := json.Unmarshal(decryptedData, &req); err != nil {
		return ModeSwitchRequest{}, err
	}

	return req, nil
}

// LogModeSwitch logs the details of a mode switch request
func (dms *DualModeSwitch) LogModeSwitch(req ModeSwitchRequest) error {
	logRecord := map[string]interface{}{
		"token_id":  req.TokenID,
		"new_mode":  req.NewMode,
		"condition": req.Condition,
		"timestamp": security.GetCurrentTimestamp(),
	}

	return dms.storage.Put("mode_switch_log_"+security.GenerateUUID(), logRecord)
}
