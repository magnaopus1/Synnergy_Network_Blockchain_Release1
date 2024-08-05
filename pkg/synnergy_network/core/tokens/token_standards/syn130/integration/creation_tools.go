package integration

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "sync"
    "time"

    "golang.org/x/crypto/scrypt"
    "golang.org/x/crypto/argon2"
)

// Syn130 represents a token with comprehensive attributes.
type Syn130 struct {
	ID                    string
	Name                  string
	Owner                 string
	Value                 float64
	
	Metadata              map[string]string
	SaleHistory           []SaleRecord
	LeaseTerms            []LeaseTerms
	LicenseTerms          []LicenseTerms
	RentalTerms           []RentalTerms
	CoOwnershipAgreements []CoOwnershipAgreement
	AssetType             string
	Classification        string
	IoTData               map[string]string
	CreationDate          time.Time
	LastUpdated           time.Time
	TransactionHistory    []TransactionRecord
	Provenance            []ProvenanceRecord
	Interoperability      InteroperabilityDetails
	Scalability           ScalabilityDetails
	AssetCategory         string
	AssetClassification   string
	AssetMetadata         AssetMetadata
	PeggedAsset           PeggedAsset
	TrackedAsset          TrackedAsset
	AssetStatus           AssetStatus
	AssetValuation        AssetValuation
	IoTDevice             IoTDevice
	LeaseAgreement        LeaseAgreement
	LicenseAgreement      LicenseAgreement
	RentalAgreement       RentalAgreement
	Lock                  sync.RWMutex
}


// SaleRecord represents a sale record of a token.
type SaleRecord struct {
    Buyer   string
    Seller  string
    Price   float64
    Date    time.Time
}

// LeaseTerms represents the lease terms for a token.
type LeaseTerms struct {
    Leasee       string
    StartDate    time.Time
    EndDate      time.Time
    PaymentTerms string
    Notifications []Notification
}

// LicenseTerms represents the licensing terms for a token.
type LicenseTerms struct {
    Licensee      string
    StartDate     time.Time
    EndDate       time.Time
    LicenseScope  string
    PaymentTerms  string
    Notifications []Notification
}

// RentalTerms represents the rental terms for a token.
type RentalTerms struct {
    Renter        string
    StartDate     time.Time
    EndDate       time.Time
    RentalRate    float64
    PaymentTerms  string
    Notifications []Notification
}

// TransactionRecord represents a transaction record for the token.
type TransactionRecord struct {
    From    string
    To      string
    Amount  float64
    Date    time.Time
    Details string
}

// ProvenanceRecord represents the provenance record for the token.
type ProvenanceRecord struct {
    Owner   string
    Date    time.Time
    Details string
}

// Notification represents a notification related to lease, license, or rental terms.
type Notification struct {
    Message     string
    Date        time.Time
    NotificationType string
}

// TokenCreationTools provides tools for creating and managing tokens.
type TokenCreationTools struct{}

// NewTokenCreationTools creates a new instance of TokenCreationTools.
func NewTokenCreationTools() *TokenCreationTools {
    return &TokenCreationTools{}
}

// CreateToken creates a new token with the given details.
func (tct *TokenCreationTools) CreateToken(name, owner, assetType, classification string, value float64) *Syn130 {
    return &Syn130{
        ID:               generateTokenID(),
        Name:             name,
        Owner:            owner,
        Value:            value,
        Metadata:         make(map[string]string),
        SaleHistory:      []SaleRecord{},
        LeaseTerms:       []LeaseTerms{},
        LicenseTerms:     []LicenseTerms{},
        RentalTerms:      []RentalTerms{},
        AssetType:        assetType,
        Classification:   classification,
        IoTData:          make(map[string]string),
        CreationDate:     time.Now(),
        LastUpdated:      time.Now(),
        TransactionHistory: []TransactionRecord{},
        Provenance:       []ProvenanceRecord{},
    }
}

// AddSaleRecord adds a sale record to the token.
func (token *Syn130) AddSaleRecord(buyer, seller string, price float64, date time.Time) {
    token.Lock.Lock()
    defer token.Lock.Unlock()
    token.SaleHistory = append(token.SaleHistory, SaleRecord{
        Buyer:  buyer,
        Seller: seller,
        Price:  price,
        Date:   date,
    })
    token.LastUpdated = time.Now()
}

// AddLeaseTerms adds lease terms to the token.
func (token *Syn130) AddLeaseTerms(leasee, paymentTerms string, startDate, endDate time.Time, notifications []Notification) {
    token.Lock.Lock()
    defer token.Lock.Unlock()
    token.LeaseTerms = append(token.LeaseTerms, LeaseTerms{
        Leasee:       leasee,
        StartDate:    startDate,
        EndDate:      endDate,
        PaymentTerms: paymentTerms,
        Notifications: notifications,
    })
    token.LastUpdated = time.Now()
}

// AddLicenseTerms adds licensing terms to the token.
func (token *Syn130) AddLicenseTerms(licensee, licenseScope, paymentTerms string, startDate, endDate time.Time, notifications []Notification) {
    token.Lock.Lock()
    defer token.Lock.Unlock()
    token.LicenseTerms = append(token.LicenseTerms, LicenseTerms{
        Licensee:      licensee,
        StartDate:     startDate,
        EndDate:       endDate,
        LicenseScope:  licenseScope,
        PaymentTerms:  paymentTerms,
        Notifications: notifications,
    })
    token.LastUpdated = time.Now()
}

// AddRentalTerms adds rental terms to the token.
func (token *Syn130) AddRentalTerms(renter string, rentalRate float64, paymentTerms string, startDate, endDate time.Time, notifications []Notification) {
    token.Lock.Lock()
    defer token.Lock.Unlock()
    token.RentalTerms = append(token.RentalTerms, RentalTerms{
        Renter:        renter,
        StartDate:     startDate,
        EndDate:       endDate,
        RentalRate:    rentalRate,
        PaymentTerms:  paymentTerms,
        Notifications: notifications,
    })
    token.LastUpdated = time.Now()
}

// AddTransactionRecord adds a transaction record to the token.
func (token *Syn130) AddTransactionRecord(from, to string, amount float64, date time.Time, details string) {
    token.Lock.Lock()
    defer token.Lock.Unlock()
    token.TransactionHistory = append(token.TransactionHistory, TransactionRecord{
        From:    from,
        To:      to,
        Amount:  amount,
        Date:    date,
        Details: details,
    })
    token.LastUpdated = time.Now()
}

// AddProvenanceRecord adds a provenance record to the token.
func (token *Syn130) AddProvenanceRecord(owner, details string, date time.Time) {
    token.Lock.Lock()
    defer token.Lock.Unlock()
    token.Provenance = append(token.Provenance, ProvenanceRecord{
        Owner:   owner,
        Date:    date,
        Details: details,
    })
    token.LastUpdated = time.Now()
}

// generateTokenID generates a unique ID for a token.
func generateTokenID() string {
    hash := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
    return hex.EncodeToString(hash[:])
}

// EncryptData encrypts the given data using AES.
func EncryptData(data, passphrase string) (string, error) {
    salt := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return "", err
    }

    key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    encryptedData := gcm.Seal(nonce, nonce, []byte(data), nil)
    return hex.EncodeToString(append(salt, encryptedData...)), nil
}

// DecryptData decrypts the given encrypted data using AES.
func DecryptData(encryptedData, passphrase string) (string, error) {
    data, err := hex.DecodeString(encryptedData)
    if err != nil {
        return "", err
    }

    salt := data[:16]
    ciphertext := data[16:]

    key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return "", errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(decryptedData), nil
}
