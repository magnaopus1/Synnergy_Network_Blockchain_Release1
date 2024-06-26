package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/argon2"
)

const (
	ScryptN       = 32768
	ScryptR       = 8
	ScryptP       = 1
	Argon2Time    = 1
	Argon2Memory  = 64 * 1024
	Argon2Threads = 4
	Argon2KeyLen  = 32
)

// GenerateKeyPair generates an ECDSA keypair
func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

// EncryptAES encrypts data using AES-GCM
func EncryptAES(data, passphrase []byte) (string, error) {
	key := argon2.IDKey(passphrase, nil, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	block, err := aes.NewCipher(key)
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

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts data using AES-GCM
func DecryptAES(encrypted string, passphrase []byte) ([]byte, error) {
	key := argon2.IDKey(passphrase, nil, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	data, err := hex.DecodeString(encrypted)
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

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// GenerateMnemonic generates a mnemonic phrase
func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(MnemonicEntropySize)
	if err != nil {
		return "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}

	return mnemonic, nil
}

// MnemonicToSeed converts a mnemonic to a seed
func MnemonicToSeed(mnemonic, passphrase string) ([]byte, error) {
	return bip39.NewSeedWithErrorChecking(mnemonic, passphrase)
}

// GenerateHDKeyFromSeed generates an HD key from a seed
func GenerateHDKeyFromSeed(seed []byte) (*hdkeychain.ExtendedKey, error) {
	return hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
}

// CalculateBalance calculates the balance of a wallet from its transactions
func CalculateBalance(address string, transactions []Transaction) (float64, error) {
	var balance float64
	for _, tx := range transactions {
		if tx.ToAddress == address {
			balance += tx.Amount
		}
		if tx.FromAddress == address {
			balance -= tx.Amount
		}
	}
	return balance, nil
}

// HashSHA256 hashes data using SHA-256
func HashSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// GenerateAddressFromPublicKey generates a wallet address from a public key
func GenerateAddressFromPublicKey(pubKey *ecdsa.PublicKey) (string, error) {
	pubKeyBytes := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	hash := HashSHA256(pubKeyBytes)
	return hex.EncodeToString(hash), nil
}

// EncryptMnemonic encrypts a mnemonic phrase using AES
func EncryptMnemonic(mnemonic, passphrase string) (string, error) {
	return EncryptAES([]byte(mnemonic), []byte(passphrase))
}

// DecryptMnemonic decrypts an encrypted mnemonic phrase using AES
func DecryptMnemonic(encrypted, passphrase string) (string, error) {
	decrypted, err := DecryptAES(encrypted, []byte(passphrase))
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// ValidateAddress validates a wallet address
func ValidateAddress(address string) bool {
	_, err := hex.DecodeString(address)
	return err == nil
}

// VerifySignature verifies the signature of a message
func VerifySignature(pubKey *ecdsa.PublicKey, message, signature []byte) bool {
	r := big.Int{}
	s := big.Int{}
	sigLen := len(signature)
	r.SetBytes(signature[:(sigLen / 2)])
	s.SetBytes(signature[(sigLen / 2):])

	hash := HashSHA256(message)
	return ecdsa.Verify(pubKey, hash, &r, &s)
}
