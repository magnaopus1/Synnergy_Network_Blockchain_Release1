package address

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/ripemd160"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/jinzhu/gorm"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/argon2"
)

// Address structure represents a blockchain address
type Address struct {
	gorm.Model
	Address    string
	PublicKey  string
	PrivateKey string
	Metadata   string
}

// GenerateAddress creates a new blockchain address
func GenerateAddress() (*Address, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	publicKey := append(privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes()...)
	address := PublicKeyToAddress(publicKey)

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return &Address{
		Address:    address,
		PublicKey:  hex.EncodeToString(publicKey),
		PrivateKey: hex.EncodeToString(privateKeyBytes),
	}, nil
}

// PublicKeyToAddress converts a public key to a blockchain address
func PublicKeyToAddress(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	ripemd160Hasher := ripemd160.New()
	ripemd160Hasher.Write(hash[:])
	publicRipeMd := ripemd160Hasher.Sum(nil)

	// Adding version byte (0x00 for mainnet) in front of RIPEMD-160 hash
	versionedPayload := append([]byte{0x00}, publicRipeMd...)

	// Double hashing with SHA-256
	hash = sha256.Sum256(versionedPayload)
	hash = sha256.Sum256(hash[:])

	// Taking first 4 bytes as checksum
	checksum := hash[:4]

	// Concatenating versioned payload and checksum
	finalPayload := append(versionedPayload, checksum...)

	// Converting to base58
	address := base58.Encode(finalPayload)

	return address
}

// EncryptPrivateKey encrypts the private key using a passphrase
func EncryptPrivateKey(privateKey, passphrase string) (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
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
	_, err = rand.Read(nonce)
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(privateKey), nil)
	return fmt.Sprintf("%x:%x", salt, ciphertext), nil
}

// DecryptPrivateKey decrypts the private key using a passphrase
func DecryptPrivateKey(encryptedPrivateKey, passphrase string) (string, error) {
	parts := strings.Split(encryptedPrivateKey, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted private key format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(parts[1])
	if err != nil {
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

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// AddMetadata adds metadata to the address
func (a *Address) AddMetadata(key, value string) {
	metadata := map[string]string{}
	metadataBytes := []byte(a.Metadata)
	if len(metadataBytes) > 0 {
		json.Unmarshal(metadataBytes, &metadata)
	}
	metadata[key] = value
	metadataBytes, _ = json.Marshal(metadata)
	a.Metadata = string(metadataBytes)
}

// ToJSON serializes the address to JSON
func (a *Address) ToJSON() (string, error) {
	jsonBytes, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// InitializeDatabase initializes the database connection
func InitializeDatabase() (*gorm.DB, error) {
	db, err := gorm.Open("sqlite3", "blockchain.db")
	if err != nil {
		return nil, err
	}

	db.AutoMigrate(&Address{}, &BlacklistedAddress{}, &WhitelistedAddress{}, &Metadata{}, &CrossChainAddress{}, &AddressAnalytics{}, &Transaction{})
	if err != nil {
		return nil, err
	}

	return db, nil
}

// BlacklistAddress adds an address to the blacklist
func BlacklistAddress(db *gorm.DB, address string) error {
	blacklistedAddress := BlacklistedAddress{Address: address}
	if err := db.Create(&blacklistedAddress).Error; err != nil {
		return err
	}
	return nil
}

// WhitelistAddress adds an address to the whitelist
func WhitelistAddress(db *gorm.DB, address string) error {
	whitelistedAddress := WhitelistedAddress{Address: address}
	if err := db.Create(&whitelistedAddress).Error; err != nil {
		return err
	}
	return nil
}

// IsAddressBlacklisted checks if an address is blacklisted
func IsAddressBlacklisted(db *gorm.DB, address string) (bool, error) {
	var blacklistedAddress BlacklistedAddress
	result := db.First(&blacklistedAddress, "address = ?", address)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return false, nil
	} else if result.Error != nil {
		return false, result.Error
	}
	return true, nil
}

// IsAddressWhitelisted checks if an address is whitelisted
func IsAddressWhitelisted(db *gorm.DB, address string) (bool, error) {
	var whitelistedAddress WhitelistedAddress
	result := db.First(&whitelistedAddress, "address = ?", address)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return false, nil
	} else if result.Error != nil {
		return false, result.Error
	}
	return true, nil
}

// Metadata structure and methods for storing and retrieving metadata associated with addresses
type Metadata struct {
	gorm.Model
	AddressID uint
	Key       string
	Value     string
}

// AddMetadataEntry adds a metadata entry to the database
func AddMetadataEntry(db *gorm.DB, addressID uint, key, value string) error {
	metadata := Metadata{AddressID: addressID, Key: key, Value: value}
	if err := db.Create(&metadata).Error; err != nil {
		return err
	}
	return nil
}

// GetMetadata retrieves metadata for a given address
func GetMetadata(db *gorm.DB, addressID uint) (map[string]string, error) {
	var metadataEntries []Metadata
	if err := db.Where("address_id = ?", addressID).Find(&metadataEntries).Error; err != nil {
		return nil, err
	}

	metadata := make(map[string]string)
	for _, entry := range metadataEntries {
		metadata[entry.Key] = entry.Value
	}

	return metadata, nil
}

// Dynamic Address Assignment
func GenerateNewAddressForTransaction(privateKey *ecdsa.PrivateKey) (string, error) {
	publicKey := &privateKey.PublicKey
	newAddress := PublicKeyToAddress(elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y))
	return newAddress, nil
}

// Cross-Chain Address Compatibility
type CrossChainAddress struct {
	gorm.Model
	Address        string
	CrossChainData string // JSON string to store cross-chain compatibility data
}

func AddCrossChainData(db *gorm.DB, address string, data map[string]string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	crossChainAddress := CrossChainAddress{Address: address, CrossChainData: string(jsonData)}
	if err := db.Create(&crossChainAddress).Error; err != nil {
		return err
	}
	return nil
}

func GetCrossChainData(db *gorm.DB, address string) (map[string]string, error) {
	var crossChainAddress CrossChainAddress
	if err := db.First(&crossChainAddress, "address = ?", address).Error; err != nil {
		return nil, err
	}

	var data map[string]string
	err := json.Unmarshal([]byte(crossChainAddress.CrossChainData), &data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Address Analytics
type AddressAnalytics struct {
	gorm.Model
	AddressID uint
	Analytics string // JSON string to store analytics data
}

func AddAnalyticsData(db *gorm.DB, addressID uint, data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	analytics := AddressAnalytics{AddressID: addressID, Analytics: string(jsonData)}
	if err := db.Create(&analytics).Error; err != nil {
		return err
	}
	return nil
}

func GetAnalyticsData(db *gorm.DB, addressID uint) (map[string]interface{}, error) {
	var analytics AddressAnalytics
	if err := db.First(&analytics, "address_id = ?", addressID).Error; err != nil {
		return nil, err
	}

	var data map[string]interface{}
	err := json.Unmarshal([]byte(analytics.Analytics), &data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Secure Encrypted Communication Channels
type SecureChannel struct {
	block cipher.Block
	iv    []byte
}

func NewSecureChannel(key []byte) (*SecureChannel, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	return &SecureChannel{
		block: block,
		iv:    iv,
	}, nil
}

func (sc *SecureChannel) Encrypt(data []byte) ([]byte, error) {
	ciphertext := make([]byte, aes.BlockSize+len(data))
	copy(ciphertext[:aes.BlockSize], sc.iv)

	stream := cipher.NewCFBEncrypter(sc.block, sc.iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func (sc *SecureChannel) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(sc.block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// Initialize all necessary components for real-world usage
func InitializeComponents() (*gorm.DB, error) {
	db, err := InitializeDatabase()
	if err != nil {
		return nil, err
	}

	return db, nil
}
