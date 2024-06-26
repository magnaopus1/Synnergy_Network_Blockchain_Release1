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

