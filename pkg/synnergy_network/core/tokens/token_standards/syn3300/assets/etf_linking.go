package assets

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/transactions"
)

// ETFLink represents the linking information of an ETF share
type ETFLink struct {
	ETFID        string    `json:"etf_id"`
	ShareTokenID string    `json:"share_token_id"`
	Owner        string    `json:"owner"`
	Timestamp    time.Time `json:"timestamp"`
}

// ETFLinkingService provides methods to link ETF shares to specific ETFs
type ETFLinkingService struct {
	ledgerService *ledger.LedgerService
}

// NewETFLinkingService creates a new instance of ETFLinkingService
func NewETFLinkingService(ledgerService *ledger.LedgerService) *ETFLinkingService {
	return &ETFLinkingService{ledgerService: ledgerService}
}

// LinkETFShare links a share token to an ETF and records the linking in the ledger
func (s *ETFLinkingService) LinkETFShare(etfID, shareTokenID, owner string) (*ETFLink, error) {
	// Validate inputs
	if etfID == "" || shareTokenID == "" || owner == "" {
		return nil, errors.New("invalid input parameters")
	}

	// Create a new ETF link
	link := &ETFLink{
		ETFID:        etfID,
		ShareTokenID: shareTokenID,
		Owner:        owner,
		Timestamp:    time.Now(),
	}

	// Record the link in the ledger
	if err := s.ledgerService.RecordETFLink(link); err != nil {
		return nil, err
	}

	return link, nil
}

// VerifyETFLink verifies the ownership of an ETF share token
func (s *ETFLinkingService) VerifyETFLink(shareTokenID, owner string) (bool, error) {
	// Retrieve the ETF link from the ledger
	link, err := s.ledgerService.GetETFLink(shareTokenID)
	if err != nil {
		return false, err
	}

	// Verify the ownership
	if link.Owner == owner {
		return true, nil
	}

	return false, errors.New("ownership verification failed")
}

// GenerateShareTokenID generates a unique token ID for an ETF share
func GenerateShareTokenID(etfID string, owner string, salt string) (string, error) {
	if etfID == "" || owner == "" || salt == "" {
		return "", errors.New("invalid input parameters")
	}

	data := etfID + owner + salt
	hash := sha256.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// EncryptionService handles encryption-related operations
type EncryptionService struct{}

// EncryptData encrypts the given data using the most secure method for the situation
func (e *EncryptionService) EncryptData(data string) (string, error) {
	// Use Argon2 for encryption
	encryptedData, err := encryption.Argon2Encrypt(data)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptData decrypts the given data using the most secure method for the situation
func (e *EncryptionService) DecryptData(encryptedData string) (string, error) {
	// Use Argon2 for decryption
	decryptedData, err := encryption.Argon2Decrypt(encryptedData)
	if err != nil {
		return "", err
	}
	return decryptedData, nil
}
