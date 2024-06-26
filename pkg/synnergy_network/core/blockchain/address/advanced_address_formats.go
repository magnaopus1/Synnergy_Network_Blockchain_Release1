package address

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"

	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/scrypt"

	"github.com/btcsuite/btcutil/base58"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Address represents a blockchain address with metadata.
type Address struct {
	PublicKey  string
	PrivateKey string
	Address    string
	Metadata   map[string]string
}

// GenerateECCKeyPair generates an ECC key pair.
func GenerateECCKeyPair() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// GenerateRSAKeyPair generates an RSA key pair.
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// PublicKeyToAddress generates a blockchain address from an ECC public key.
func PublicKeyToAddress(pubKey *ecdsa.PublicKey) string {
	pubKeyBytes := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	hashSHA256 := sha256.New()
	hashSHA256.Write(pubKeyBytes)
	hash := hashSHA256.Sum(nil)

	hashRIPEMD160 := ripemd160.New()
	hashRIPEMD160.Write(hash)
	publicRIPEMD160 := hashRIPEMD160.Sum(nil)

	versionedPayload := append([]byte{0x00}, publicRIPEMD160...)
	checksum := Checksum(versionedPayload)
	fullPayload := append(versionedPayload, checksum...)
	address := base58.Encode(fullPayload)

	return address
}

// Checksum generates a checksum for the address.
func Checksum(payload []byte) []byte {
	hashSHA256 := sha256.Sum256(payload)
	secondSHA256 := sha256.Sum256(hashSHA256[:])
	return secondSHA256[:4]
}

// GenerateAddress generates a new blockchain address.
func GenerateAddress() (*Address, error) {
	privateKey, err := GenerateECCKeyPair()
	if err != nil {
		return nil, err
	}

	publicKey := &privateKey.PublicKey
	address := PublicKeyToAddress(publicKey)

	privKeyBytes := privateKey.D.Bytes()
	privateKeyStr := hex.EncodeToString(privKeyBytes)

	return &Address{
		PublicKey:  hex.EncodeToString(elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)),
		PrivateKey: privateKeyStr,
		Address:    address,
		Metadata:   make(map[string]string),
	}, nil
}

// AddMetadata adds metadata to the address.
func (a *Address) AddMetadata(key, value string) {
	a.Metadata[key] = value
}

// ToJSON serializes the address to JSON.
func (a *Address) ToJSON() (string, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON deserializes the address from JSON.
func FromJSON(data string) (*Address, error) {
	var address Address
	err := json.Unmarshal([]byte(data), &address)
	if err != nil {
		return nil, err
	}
	return &address, nil
}

// LoadBlacklistedAddresses loads blacklisted addresses from a file.
func LoadBlacklistedAddresses(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var addresses []string
	err = json.NewDecoder(file).Decode(&addresses)
	if err != nil {
		return nil, err
	}

	return addresses, nil
}

// SaveBlacklistedAddresses saves blacklisted addresses to a file.
func SaveBlacklistedAddresses(filename string, addresses []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	err = json.NewEncoder(file).Encode(addresses)
	if err != nil {
		return err
	}

	return nil
}

// LoadWhitelistedAddresses loads whitelisted addresses from a file.
func LoadWhitelistedAddresses(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var addresses []string
	err = json.NewDecoder(file).Decode(&addresses)
	if err != nil {
		return nil, err
	}

	return addresses, nil
}

// SaveWhitelistedAddresses saves whitelisted addresses to a file.
func SaveWhitelistedAddresses(filename string, addresses []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	err = json.NewEncoder(file).Encode(addresses)
	if err != nil {
		return err
	}

	return nil
}

// EncryptPrivateKey encrypts a private key using Scrypt and AES.
func EncryptPrivateKey(privateKey string, passphrase string) (string, error) {
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

	plaintext := []byte(privateKey)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return hex.EncodeToString(ciphertext), nil
}

// DecryptPrivateKey decrypts a private key using Scrypt and AES.
func DecryptPrivateKey(encryptedPrivateKey string, passphrase string) (string, error) {
	ciphertext, err := hex.DecodeString(encryptedPrivateKey)
	if err != nil {
		return "", err
	}

	salt := ciphertext[:16]
	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := ciphertext[aes.BlockSize:]
	plaintext := make([]byte, len(ciphertext)-aes.BlockSize)
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

	return string(plaintext), nil
}

// AuthorizeTransaction signs a transaction with the private key.
func (a *Address) AuthorizeTransaction(transaction string, passphrase string) (string, error) {
	privateKeyHex, err := DecryptPrivateKey(a.PrivateKey, passphrase)
	if err != nil {
		return "", err
	}

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", err
	}

	privateKey := new(ecdsa.PrivateKey)
	privateKey.D = new(big.Int).SetBytes(privateKeyBytes)
	privateKey.PublicKey.Curve = elliptic.P256()
	privateKey.PublicKey.X, privateKey.PublicKey.Y = elliptic.Unmarshal(elliptic.P256(), []byte(a.PublicKey))

	hash := sha256.Sum256([]byte(transaction))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", err
	}

	signature := append(r.Bytes(), s.Bytes()...)
	return hex.EncodeToString(signature), nil
}

// VerifyTransaction verifies a signed transaction.
func VerifyTransaction(transaction string, signature string, publicKey string) (bool, error) {
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, err
	}

	r := new(big.Int).SetBytes(sigBytes[:len(sigBytes)/2])
	s := new(big.Int).SetBytes(sigBytes[len(sigBytes)/2:])

	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return false, err
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)
	if x == nil {
		return false, errors.New("invalid public key")
	}

	pubKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	hash := sha256.Sum256([]byte(transaction))
	return ecdsa.Verify(&pubKey, hash[:], r, s), nil
}

// Database models for blacklisted and whitelisted addresses
type BlacklistedAddress struct {
	gorm.Model
	Address string `gorm:"uniqueIndex"`
}

type WhitelistedAddress struct {
	gorm.Model
	Address string `gorm:"uniqueIndex"`
}

// InitializeDatabase initializes the database for storing blacklisted and whitelisted addresses.
func InitializeDatabase() (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open("addresses.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	err = db.AutoMigrate(&BlacklistedAddress{}, &WhitelistedAddress{})
	if err != nil {
		return nil, err
	}

	return db, nil
}

// BlacklistAddress adds an address to the blacklist.
func BlacklistAddress(db *gorm.DB, address string) error {
	blacklistedAddress := BlacklistedAddress{Address: address}
	if err := db.Create(&blacklistedAddress).Error; err != nil {
		return err
	}
	return nil
}

// WhitelistAddress adds an address to the whitelist.
func WhitelistAddress(db *gorm.DB, address string) error {
	whitelistedAddress := WhitelistedAddress{Address: address}
	if err := db.Create(&whitelistedAddress).Error; err != nil {
		return err
	}
	return nil
}

// IsAddressBlacklisted checks if an address is blacklisted.
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

// IsAddressWhitelisted checks if an address is whitelisted.
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

// AddMetadataEntry adds a metadata entry to the database.
func AddMetadataEntry(db *gorm.DB, addressID uint, key, value string) error {
	metadata := Metadata{AddressID: addressID, Key: key, Value: value}
	if err := db.Create(&metadata).Error; err != nil {
		return err
	}
	return nil
}

// GetMetadata retrieves metadata for a given address.
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
	newAddress := PublicKeyToAddress(publicKey)
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
	Address         string
	TransactionCount uint
	TotalReceived    float64
	TotalSent        float64
}

func UpdateAddressAnalytics(db *gorm.DB, address string, received, sent float64) error {
	var analytics AddressAnalytics
	if err := db.FirstOrCreate(&analytics, AddressAnalytics{Address: address}).Error; err != nil {
		return err
	}

	analytics.TransactionCount++
	analytics.TotalReceived += received
	analytics.TotalSent += sent

	if err := db.Save(&analytics).Error; err != nil {
		return err
	}
	return nil
}

func GetAddressAnalytics(db *gorm.DB, address string) (AddressAnalytics, error) {
	var analytics AddressAnalytics
	if err := db.First(&analytics, "address = ?", address).Error; err != nil {
		return AddressAnalytics{}, err
	}
	return analytics, nil
}
