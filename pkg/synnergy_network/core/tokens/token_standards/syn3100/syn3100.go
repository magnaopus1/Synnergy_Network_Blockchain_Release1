package syn3100

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/events"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/smart_contracts"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/storage"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/transactions"
)

type SYN3100Token struct {
	TokenID       string    `json:"token_id"`
	ContractID    string    `json:"contract_id"`
	EmployeeID    string    `json:"employee_id"`
	EmployerID    string    `json:"employer_id"`
	Position      string    `json:"position"`
	Salary        float64   `json:"salary"`
	ContractType  string    `json:"contract_type"`
	StartDate     time.Time `json:"start_date"`
	EndDate       time.Time `json:"end_date"`
	Benefits      string    `json:"benefits"`
	ContractTerms string    `json:"contract_terms"`
	ActiveStatus  bool      `json:"active_status"`
	IssueDate     time.Time `json:"issue_date"`
}

type SYN3100 struct {
	ledger           *ledger.EmploymentTransactionLedger
	securityManager  *security.SecurityManager
	storageManager   *storage.DatabaseManagement
	contractLinker   *assets.ContractLinking
	ownershipVer     *assets.OwnershipVerification
	contractManager  *smart_contracts.SmartContractIntegration
	eventManager     *events.EventManager
	transactions     *transactions.TransactionManager
	encryptionKey    []byte
}

// NewSYN3100 initializes a new SYN3100 instance
func NewSYN3100(encryptionKey []byte) (*SYN3100, error) {
	if len(encryptionKey) == 0 {
		return nil, errors.New("encryption key cannot be empty")
	}

	ledger := ledger.NewEmploymentTransactionLedger()
	securityManager := security.NewSecurityManager()
	storageManager := storage.NewDatabaseManagement()
	contractLinker := assets.NewContractLinking()
	ownershipVer := assets.NewOwnershipVerification()
	contractManager := smart_contracts.NewSmartContractIntegration()
	eventManager := events.NewEventManager()
	transactions := transactions.NewTransactionManager()

	return &SYN3100{
		ledger:          ledger,
		securityManager: securityManager,
		storageManager:  storageManager,
		contractLinker:  contractLinker,
		ownershipVer:    ownershipVer,
		contractManager: contractManager,
		eventManager:    eventManager,
		transactions:    transactions,
		encryptionKey:   encryptionKey,
	}, nil
}

// IssueToken issues a new employment token
func (s *SYN3100) IssueToken(token SYN3100Token) error {
	token.IssueDate = time.Now()
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return err
	}

	encryptedToken, err := s.securityManager.Encrypt(tokenBytes, s.encryptionKey)
	if err != nil {
		return err
	}

	err = s.storageManager.StoreData(token.TokenID, encryptedToken)
	if err != nil {
		return err
	}

	err = s.ledger.RecordTransaction(token.TokenID, token.ContractID, "issue", tokenBytes)
	if err != nil {
		return err
	}

	s.eventManager.EmitEvent("TokenIssued", token.TokenID)

	return nil
}

// TransferToken transfers an employment token from one owner to another
func (s *SYN3100) TransferToken(tokenID, newOwnerID string) error {
	tokenData, err := s.loadToken(tokenID)
	if err != nil {
		return err
	}

	var token SYN3100Token
	err = json.Unmarshal(tokenData, &token)
	if err != nil {
		return err
	}

	token.EmployeeID = newOwnerID
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return err
	}

	encryptedToken, err := s.securityManager.Encrypt(tokenBytes, s.encryptionKey)
	if err != nil {
		return err
	}

	err = s.storageManager.StoreData(tokenID, encryptedToken)
	if err != nil {
		return err
	}

	err = s.ledger.RecordTransaction(tokenID, token.ContractID, "transfer", tokenBytes)
	if err != nil {
		return err
	}

	s.eventManager.EmitEvent("TokenTransferred", tokenID)

	return nil
}

// RevokeToken revokes an employment token
func (s *SYN3100) RevokeToken(tokenID string) error {
	tokenData, err := s.loadToken(tokenID)
	if err != nil {
		return err
	}

	var token SYN3100Token
	err = json.Unmarshal(tokenData, &token)
	if err != nil {
		return err
	}

	token.ActiveStatus = false
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return err
	}

	encryptedToken, err := s.securityManager.Encrypt(tokenBytes, s.encryptionKey)
	if err != nil {
		return err
	}

	err = s.storageManager.StoreData(tokenID, encryptedToken)
	if err != nil {
		return err
	}

	err = s.ledger.RecordTransaction(tokenID, token.ContractID, "revoke", tokenBytes)
	if err != nil {
		return err
	}

	s.eventManager.EmitEvent("TokenRevoked", tokenID)

	return nil
}

// GetToken retrieves an employment token
func (s *SYN3100) GetToken(tokenID string) (*SYN3100Token, error) {
	tokenData, err := s.loadToken(tokenID)
	if err != nil {
		return nil, err
	}

	var token SYN3100Token
	err = json.Unmarshal(tokenData, &token)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

// loadToken loads a token by its ID
func (s *SYN3100) loadToken(tokenID string) ([]byte, error) {
	data, err := s.storageManager.LoadData(tokenID)
	if err != nil {
		return nil, err
	}

	decryptedData, err := s.securityManager.Decrypt(data, s.encryptionKey)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// ListTokens lists all employment tokens
func (s *SYN3100) ListTokens() ([]SYN3100Token, error) {
	tokenIDs, err := s.storageManager.ListKeys()
	if err != nil {
		return nil, err
	}

	var tokens []SYN3100Token
	for _, tokenID := range tokenIDs {
		tokenData, err := s.loadToken(tokenID)
		if err != nil {
			return nil, err
		}

		var token SYN3100Token
		err = json.Unmarshal(tokenData, &token)
		if err != nil {
			return nil, err
		}

		tokens = append(tokens, token)
	}

	return tokens, nil
}
