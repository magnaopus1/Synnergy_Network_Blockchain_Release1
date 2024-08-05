// Package assets provides functionalities for linking agricultural tokens to real-world assets in the SYN4900 Token Standard.
package assets

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/synnergy_network/encryption"
	"github.com/synnergy_network/ledger"
	"github.com/synnergy_network/compliance"
)

// AssetLink represents the linkage between an agricultural token and a real-world agricultural asset.
type AssetLink struct {
	TokenID         string `json:"token_id"`
	AssetID         string `json:"asset_id"`
	AssetDetails    string `json:"asset_details"`
	LinkDate        time.Time `json:"link_date"`
	VerificationStatus bool   `json:"verification_status"`
}

// LinkAssetToToken links an agricultural asset to a token by recording the asset ID and details.
func LinkAssetToToken(token *AgriculturalToken, assetID, assetDetails string) (*AssetLink, error) {
	if token == nil || assetID == "" {
		return nil, errors.New("invalid token or asset ID")
	}

	// Create an AssetLink structure
	assetLink := &AssetLink{
		TokenID:         token.TokenID,
		AssetID:         assetID,
		AssetDetails:    assetDetails,
		LinkDate:        time.Now(),
		VerificationStatus: false, // Initial status; requires verification
	}

	// Log linkage in the ledger
	if err := ledger.LogAssetLink(assetLink); err != nil {
		return nil, err
	}

	return assetLink, nil
}

// VerifyAssetLink verifies the linkage between an agricultural token and its associated real-world asset.
func VerifyAssetLink(assetLink *AssetLink) error {
	if assetLink == nil {
		return errors.New("invalid asset link")
	}

	// Assume verification involves checking real-world documentation or compliance records
	verified := compliance.VerifyAssetDocumentation(assetLink.AssetID)
	if verified {
		assetLink.VerificationStatus = true
		return ledger.UpdateVerificationStatus(assetLink.TokenID, true)
	}

	return errors.New("verification failed for asset link")
}

// EncryptAssetLink encrypts the details of the asset link.
func EncryptAssetLink(assetLink *AssetLink, passphrase string) (string, error) {
	data, err := json.Marshal(assetLink)
	if err != nil {
		return "", err
	}
	encryptedData, err := encryption.EncryptData(data, passphrase)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptAssetLink decrypts the details of the asset link.
func DecryptAssetLink(encryptedData, passphrase string) (*AssetLink, error) {
	decryptedData, err := encryption.DecryptData(encryptedData, passphrase)
	if err != nil {
		return nil, err
	}
	var assetLink AssetLink
	if err := json.Unmarshal(decryptedData, &assetLink); err != nil {
		return nil, err
	}
	return &assetLink, nil
}

// LogAssetLink logs the asset linkage in the ledger for traceability and compliance.
func LogAssetLink(assetLink *AssetLink) error {
	return ledger.LogAssetLink(assetLink)
}

// UpdateVerificationStatus updates the verification status of the asset link in the ledger.
func UpdateVerificationStatus(tokenID string, status bool) error {
	return ledger.UpdateVerificationStatus(tokenID, status)
}
