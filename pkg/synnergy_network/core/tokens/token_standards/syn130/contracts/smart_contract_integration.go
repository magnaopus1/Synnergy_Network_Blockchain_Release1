package contracts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
)

// Syn130SmartContract represents a smart contract for the SYN130 Token Standard.
type Syn130SmartContract struct {
	ID                    string              `json:"id"`
	Owner                 string              `json:"owner"`
	TangibleAssetID               string              `json:"asset_id"`
	ContractType          string              `json:"contract_type"`
	Terms                 string              `json:"terms"`
	EncryptedTerms        string              `json:"encrypted_terms"`
	EncryptionKey         string              `json:"encryption_key"`
	Status                string              `json:"status"`
	TangibleAssetCategory         string              `json:"asset_category"`
	TangibleAssetClassification   string              `json:"asset_classification"`
	TangibleAssetMetadata         AssetMetadata       `json:"asset_metadata"`
	PeggedTangibleAsset           PeggedAsset         `json:"pegged_asset"`
	TrackedTangibleAsset          TrackedAsset        `json:"tracked_asset"`
	TangibleAssetStatus           AssetStatus         `json:"asset_status"`
	TangibleAssetValuation        AssetValuation      `json:"asset_valuation"`
	IoTDevice             IoTDevice           `json:"iot_device"`
	LeaseAgreement        LeaseAgreement      `json:"lease_agreement"`
	CoOwnershipAgreements []CoOwnershipAgreement `json:"co_ownership_agreements"`
	LicenseAgreement      LicenseAgreement    `json:"license_agreement"`
	RentalAgreement       RentalAgreement     `json:"rental_agreement"`
}

// AssetMetadata represents metadata related to the asset.
type TangibleAssetMetadata struct {
	Description     string
	Documentation   []string
	Images          []string
	AdditionalInfo  map[string]string
}

// PeggedAsset represents details of the asset pegging mechanism.
type PeggedTangibleAsset struct {
	ReferenceIndex string
	PeggedValue    float64
}

// TrackedAsset represents details of the asset tracking mechanism.
type TrackedTangibleAsset struct {
	TrackingID      string
	CurrentLocation string
	Status          string
}

// AssetStatus represents the current status of the asset.
type TangibleAssetStatus struct {
	Status   string
	Details  string
}

// AssetValuation represents the valuation details of the asset.
type TangibleAssetValuation struct {
	CurrentValue float64
	LastUpdated  time.Time
	ValuationHistory []ValuationRecord
}

// ValuationRecord represents a record of the asset valuation.
type ValuationRecord struct {
	Value     float64
	Timestamp time.Time
	Details   string
}

// IoTDevice represents the IoT device associated with the asset.
type IoTDevice struct {
	DeviceID   string
	DeviceType string
	Status     string
	Data       map[string]interface{}
}

// LeaseAgreement represents the lease agreement details.
type LeaseAgreement struct {
	AgreementID string
	Leasee      string
	StartDate   time.Time
	EndDate     time.Time
	Terms       string
}

// CoOwnershipAgreement represents co-ownership agreement details.
type CoOwnershipAgreement struct {
	CoOwners           []string
	OwnershipPercentage map[string]float64
	AgreementDetails    string
}

// LicenseAgreement represents the licensing agreement details.
type LicenseAgreement struct {
	AgreementID string
	Licensee    string
	StartDate   time.Time
	EndDate     time.Time
	Terms       string
}

// RentalAgreement represents the rental agreement details.
type RentalAgreement struct {
	AgreementID string
	Renter      string
	StartDate   time.Time
	EndDate     time.Time
	Terms       string
}

// NewSyn130SmartContract creates a new SYN130 smart contract.
func NewSyn130SmartContract(owner, assetID, contractType, terms string, startDate, endDate time.Time) (*Syn130SmartContract, error) {
	if owner == "" || assetID == "" || contractType == "" || terms == "" {
		return nil, errors.New("missing required fields")
	}
	id := generateID()
	encryptionKey := generateEncryptionKey()
	encryptedTerms, err := encrypt(terms, encryptionKey)
	if err != nil {
		return nil, err
	}
	return &Syn130SmartContract{
		ID:             id,
		Owner:          owner,
		AssetID:        assetID,
		ContractType:   contractType,
		Terms:          terms,
		EncryptedTerms: encryptedTerms,
		EncryptionKey:  encryptionKey,
		Status:         "active",
		StartDate:      startDate,
		EndDate:        endDate,
	}, nil
}

// Terminate terminates the SYN130 smart contract.
func (sc *Syn130SmartContract) Terminate() {
	sc.Status = "terminated"
}

// Renew renews the SYN130 smart contract with new terms and dates.
func (sc *Syn130SmartContract) Renew(newTerms string, newStartDate, newEndDate time.Time) error {
	encryptionKey := generateEncryptionKey()
	encryptedTerms, err := encrypt(newTerms, encryptionKey)
	if err != nil {
		return err
	}
	sc.Terms = newTerms
	sc.EncryptedTerms = encryptedTerms
	sc.EncryptionKey = encryptionKey
	sc.StartDate = newStartDate
	sc.EndDate = newEndDate
	sc.Status = "renewed"
	return nil
}

// VerifyTerms verifies the encrypted terms with the original terms.
func (sc *Syn130SmartContract) VerifyTerms() bool {
	decryptedTerms, err := decrypt(sc.EncryptedTerms, sc.EncryptionKey)
	if err != nil {
		return false
	}
	return sc.Terms == decryptedTerms
}

// Utility functions

func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func generateEncryptionKey() string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key := argon2.IDKey([]byte("passphrase"), salt, 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(key)
}

func encrypt(data, passphrase string) (string, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(encryptedData, passphrase string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// Additional features specific to SYN130 Token Standard

// TransferOwnership transfers the ownership of the asset associated with the smart contract.
func (sc *Syn130SmartContract) TransferOwnership(newOwner string) error {
	if newOwner == "" {
		return errors.New("new owner address is required")
	}
	sc.Owner = newOwner
	return nil
}

// LogValuation logs the valuation change of the asset.
func (sc *Syn130SmartContract) LogValuation(newValuation string) error {
	if newValuation == "" {
		return errors.New("valuation data is required")
	}
	// Simulate logging valuation change
	fmt.Printf("Asset %s valuation changed to %s\n", sc.AssetID, newValuation)
	return nil
}

// IntegrateWithLease integrates the smart contract with lease management.
func (sc *Syn130SmartContract) IntegrateWithLease(leaseID string) error {
	if leaseID == "" {
		return errors.New("lease ID is required")
	}
	// Simulate integration with lease
	fmt.Printf("Smart contract %s integrated with lease %s\n", sc.ID, leaseID)
	return nil
}

// HandleIoTData handles the integration with IoT devices for real-time data.
func (sc *Syn130SmartContract) HandleIoTData(data string) error {
	if data == "" {
		return errors.New("IoT data is required")
	}
	// Simulate handling IoT data
	fmt.Printf("Handling IoT data for asset %s: %s\n", sc.AssetID, data)
	return nil
}
