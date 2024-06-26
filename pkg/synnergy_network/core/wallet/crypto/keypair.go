package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

// KeyPair represents an ECDSA key pair.
type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  ecdsa.PublicKey
}

// GenerateKeyPair generates a new ECDSA key pair.
func GenerateKeyPair() (*KeyPair, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privKey,
		PublicKey:  privKey.PublicKey,
	}, nil
}

// SavePrivateKey saves the private key to a file, encrypted with a passphrase.
func (kp *KeyPair) SavePrivateKey(filename, passphrase string) error {
	privBytes, err := x509.MarshalECPrivateKey(kp.PrivateKey)
	if err != nil {
		return err
	}

	encryptedPrivBytes, err := encryptData(privBytes, passphrase)
	if err != nil {
		return err
	}

	privBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: encryptedPrivBytes,
	}

	privPem := pem.EncodeToMemory(privBlock)
	return ioutil.WriteFile(filename, privPem, 0600)
}

// LoadPrivateKey loads and decrypts a private key from a file using a passphrase.
func LoadPrivateKey(filename, passphrase string) (*ecdsa.PrivateKey, error) {
	privPem, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	privBlock, _ := pem.Decode(privPem)
	if privBlock == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privBytes, err := decryptData(privBlock.Bytes, passphrase)
	if err != nil {
		return nil, err
	}

	privKey, err := x509.ParseECPrivateKey(privBytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// SavePublicKey saves the public key to a file.
func (kp *KeyPair) SavePublicKey(filename string) error {
	pubBytes, err := x509.MarshalPKIXPublicKey(&kp.PublicKey)
	if err != nil {
		return err
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	pubPem := pem.EncodeToMemory(pubBlock)
	return ioutil.WriteFile(filename, pubPem, 0644)
}

// LoadPublicKey loads a public key from a file.
func LoadPublicKey(filename string) (*ecdsa.PublicKey, error) {
	pubPem, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	pubBlock, _ := pem.Decode(pubPem)
	if pubBlock == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to assert type to *ecdsa.PublicKey")
	}

	return pubKey, nil
}

// encryptData encrypts data using Scrypt for key derivation and AES for encryption.
func encryptData(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	encryptedData, err := encryptAES(data, key)
	if err != nil {
		return nil, err
	}

	return append(salt, encryptedData...), nil
}

// decryptData decrypts data using Scrypt for key derivation and AES for decryption.
func decryptData(data []byte, passphrase string) ([]byte, error) {
	if len(data) < 32 {
		return nil, errors.New("invalid data length")
	}

	salt := data[:32]
	ciphertext := data[32:]

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return decryptAES(ciphertext, key)
}

// encryptAES encrypts data using AES-GCM.
func encryptAES(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptAES decrypts data using AES-GCM.
func decryptAES(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// HashAddress hashes a public key to create a blockchain address.
func HashAddress(pubKey ecdsa.PublicKey) string {
	pubBytes := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	hash := sha3.New256()
	hash.Write(pubBytes)
	return hex.EncodeToString(hash.Sum(nil))
}

// SignData signs data using the private key.
func SignData(data []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, err
	}

	return append(r.Bytes(), s.Bytes()...), nil
}

// VerifySignature verifies the signature using the public key.
func VerifySignature(data, signature []byte, pubKey ecdsa.PublicKey) bool {
	hash := sha256.Sum256(data)
	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])
	return ecdsa.Verify(&pubKey, hash[:], r, s)
}
