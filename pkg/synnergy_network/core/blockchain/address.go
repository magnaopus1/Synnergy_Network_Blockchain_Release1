package address

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/scrypt"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"errors"
	"log"
	"os"
	"github.com/btcsuite/btcutil/base58"
)



// GenerateECCKeyPair generates an ECC key pair.
func GenerateECCKeyPair() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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



// GenerateECCKeyPair generates an ECC key pair.
func GenerateECCKeyPair() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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





// GenerateECCKeyPair generates an ECC key pair.
func GenerateECCKeyPair() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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

func (a *Address) CreateTransaction(db *gorm.DB, receiver string, amount float64, passphrase string) (*Transaction, error) {
	tx := &Transaction{
		Sender:   a.Address,
		Receiver: receiver,
		Amount:   amount,
		Status:   "pending",
	}

	txData := fmt.Sprintf("%s:%s:%f", tx.Sender, tx.Receiver, tx.Amount)
	signature, err := a.AuthorizeTransaction(txData, passphrase)
	if err != nil {
		return nil, err
	}
	tx.Signature = signature

	if err := db.Create(tx).Error; err != nil {
		return nil, err
	}
	return tx, nil
}

func VerifyAndCompleteTransaction(db *gorm.DB, tx *Transaction, senderPublicKey string) error {
	txData := fmt.Sprintf("%s:%s:%f", tx.Sender, tx.Receiver, tx.Amount)
	valid, err := VerifyTransaction(txData, tx.Signature, senderPublicKey)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid transaction signature")
	}

	tx.Status = "completed"
	if err := db.Save(tx).Error; err != nil {
		return err
	}
	return nil
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

// InitializeDatabase initializes the database for storing blacklisted and whitelisted addresses.
func InitializeDatabase() (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open("addresses.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	err = db.AutoMigrate(&BlacklistedAddress{}, &WhitelistedAddress{}, &Metadata{}, &CrossChainAddress{}, &AddressAnalytics{}, &Transaction{})
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

// CreateTransaction creates a new transaction.
func (a *Address) CreateTransaction(db *gorm.DB, receiver string, amount float64, passphrase string) (*Transaction, error) {
	tx := &Transaction{
		Sender:   a.Address,
		Receiver: receiver,
		Amount:   amount,
		Status:   "pending",
	}

	txData := fmt.Sprintf("%s:%s:%f", tx.Sender, tx.Receiver, tx.Amount)
	signature, err := a.AuthorizeTransaction(txData, passphrase)
	if err != nil {
		return nil, err
	}
	tx.Signature = signature

	if err := db.Create(tx).Error; err != nil {
		return nil, err
	}
	return tx, nil
}

// VerifyAndCompleteTransaction verifies a transaction and marks it as completed.
func VerifyAndCompleteTransaction(db *gorm.DB, tx *Transaction, senderPublicKey string) error {
	txData := fmt.Sprintf("%s:%s:%f", tx.Sender, tx.Receiver, tx.Amount)
	valid, err := VerifyTransaction(txData, tx.Signature, senderPublicKey)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid transaction signature")
	}

	tx.Status = "completed"
	if err := db.Save(tx).Error; err != nil {
		return err
	}
	return nil
}

// CreateMultiSigAddress creates a multi-signature address.
func CreateMultiSigAddress(signers []string, requiredSigns uint) (*MultiSigAddress, error) {
	signerData, err := json.Marshal(signers)
	if err != nil {
		return nil, err
	}

	return &MultiSigAddress{
		Address:       GenerateMultiSigAddress(signers),
		Signers:       signers,
		RequiredSigns: requiredSigns,
		SignerData:    string(signerData),
	}, nil
}

// GenerateMultiSigAddress generates a multi-signature address.
func GenerateMultiSigAddress(signers []string) string {
	hash := sha256.New()
	for _, signer := range signers {
		hash.Write([]byte(signer))
	}
	return base58.Encode(hash.Sum(nil))
}

// NewHDAddress generates a new HD address from a seed.
func NewHDAddress(seed []byte, index uint32) (*HDAddress, error) {
	masterKey, chainCode, err := GenerateMasterKeyAndChainCode(seed)
	if err != nil {
		return nil, err
	}

	childPrivateKey, childChainCode, err := DeriveChildKey(masterKey, chainCode, index)
	if err != nil {
		return nil, err
	}

	publicKey := PublicKeyFromPrivateKey(childPrivateKey)
	return &HDAddress{
		PrivateKey: hex.EncodeToString(childPrivateKey.D.Bytes()),
		PublicKey:  hex.EncodeToString(publicKey),
		ChainCode:  hex.EncodeToString(childChainCode),
		Index:      index,
	}, nil
}

// GenerateMasterKeyAndChainCode generates a master key and chain code from a seed.
func GenerateMasterKeyAndChainCode(seed []byte) (*ecdsa.PrivateKey, []byte, error) {
	hash := hmac.New(sha256.New, []byte("Bitcoin seed"))
	hash.Write(seed)
	I := hash.Sum(nil)
	IL, IR := I[:32], I[32:]

	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateKey.D = new(big.Int).SetBytes(IL)

	return privateKey, IR, nil
}

// DeriveChildKey derives a child key and chain code from a master key and chain code.
func DeriveChildKey(masterKey *ecdsa.PrivateKey, chainCode []byte, index uint32) (*ecdsa.PrivateKey, []byte, error) {
	indexBytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		indexBytes[i] = byte(index >> uint(8*(3-i)))
	}

	data := append([]byte{0x00}, masterKey.D.Bytes()...)
	data = append(data, indexBytes...)

	hash := hmac.New(sha256.New, chainCode)
	hash.Write(data)
	I := hash.Sum(nil)
	IL, IR := I[:32], I[32:]

	childKey := new(ecdsa.PrivateKey)
	childKey.PublicKey.Curve = elliptic.P256()
	childKey.D = new(big.Int).SetBytes(IL)
	childKey.PublicKey.X, childKey.PublicKey.Y = childKey.PublicKey.Curve.ScalarBaseMult(IL)

	return childKey, IR, nil
}

// PublicKeyFromPrivateKey derives the public key from a private key.
func PublicKeyFromPrivateKey(privateKey *ecdsa.PrivateKey) []byte {
	return elliptic.Marshal(privateKey.PublicKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
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


// GenerateAddress creates a new blockchain address
func GenerateAddress() (*Address, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	publicKey := append(privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes()...)
	address := PublicKeyToAddress(publicKey)

	return &Address{
		Address:    address,
		PublicKey:  hex.EncodeToString(publicKey),
		PrivateKey: hex.EncodeToString(x509.MarshalECPrivateKey(privateKey)),
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
