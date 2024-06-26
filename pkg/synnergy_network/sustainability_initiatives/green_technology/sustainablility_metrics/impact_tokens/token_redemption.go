package impact_tokens

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/scrypt"
	"github.com/synthron_blockchain_final/pkg/layer0/blockchain"
)

// EnvironmentalImpactToken represents a token that rewards sustainable behavior.
type EnvironmentalImpactToken struct {
	TokenID      string `json:"token_id"`
	OwnerID      string `json:"owner_id"`
	Points       int    `json:"points"`
	IssueDate    string `json:"issue_date"`
	ExpiryDate   string `json:"expiry_date"`
	Redeemed     bool   `json:"redeemed"`
}

// NewEnvironmentalImpactToken creates a new environmental impact token.
func NewEnvironmentalImpactToken(ownerID string, points int, issueDate, expiryDate string) *EnvironmentalImpactToken {
	return &EnvironmentalImpactToken{
		TokenID:   fmt.Sprintf("token-%d", rand.Int()),
		OwnerID:   ownerID,
		Points:    points,
		IssueDate: issueDate,
		ExpiryDate: expiryDate,
		Redeemed:  false,
	}
}

// SaveToken saves the environmental impact token to the blockchain.
func (token *EnvironmentalImpactToken) SaveToken() error {
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return blockchain.PutState(token.TokenID, tokenJSON)
}

// GetToken retrieves an environmental impact token from the blockchain.
func GetToken(tokenID string) (*EnvironmentalImpactToken, error) {
	tokenJSON, err := blockchain.GetState(tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from blockchain: %v", err)
	}
	if tokenJSON == nil {
		return nil, fmt.Errorf("the token %s does not exist", tokenID)
	}

	var token EnvironmentalImpactToken
	err = json.Unmarshal(tokenJSON, &token)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

// ListAllTokens lists all environmental impact tokens.
func ListAllTokens() ([]EnvironmentalImpactToken, error) {
	// Placeholder for a method to list all environmental impact tokens.
	// This would typically involve querying the blockchain ledger for all token records.
	// For now, we return an empty list.
	return []EnvironmentalImpactToken{}, nil
}

// TransferToken transfers an environmental impact token to a new owner.
func (token *EnvironmentalImpactToken) TransferToken(newOwnerID string) error {
	token.OwnerID = newOwnerID
	return token.SaveToken()
}

// TokenUpdateRequest represents a request to update an environmental impact token.
type TokenUpdateRequest struct {
	TokenID    string `json:"token_id"`
	NewOwnerID string `json:"new_owner_id"`
}

// HandleTokenUpdate handles the update request for an environmental impact token.
func HandleTokenUpdate(request TokenUpdateRequest) error {
	token, err := GetToken(request.TokenID)
	if err != nil {
		return err
	}

	err = token.TransferToken(request.NewOwnerID)
	if err != nil {
		return err
	}
	return token.SaveToken()
}

// RedeemToken redeems an environmental impact token.
func (token *EnvironmentalImpactToken) RedeemToken() error {
	if token.Redeemed {
		return errors.New("token already redeemed")
	}

	// Check if the token is expired
	expiryDate, err := time.Parse("2006-01-02", token.ExpiryDate)
	if err != nil {
		return fmt.Errorf("invalid expiry date format: %v", err)
	}

	if time.Now().After(expiryDate) {
		return errors.New("token has expired")
	}

	token.Redeemed = true
	return token.SaveToken()
}

// TokenRedemptionRequest represents a request to redeem an environmental impact token.
type TokenRedemptionRequest struct {
	TokenID string `json:"token_id"`
}

// HandleTokenRedemption handles the redemption request for an environmental impact token.
func HandleTokenRedemption(request TokenRedemptionRequest) error {
	token, err := GetToken(request.TokenID)
	if err != nil {
		return err
	}

	err = token.RedeemToken()
	if err != nil {
		return err
	}
	return token.SaveToken()
}

// EncryptData encrypts data using AES.
func EncryptData(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// DecryptData decrypts data using AES.
func DecryptData(data []byte, passphrase string) ([]byte, error) {
	if len(data) < 32 {
		return nil, errors.New("invalid data")
	}

	salt, ciphertext := data[:32], data[32:]

	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
