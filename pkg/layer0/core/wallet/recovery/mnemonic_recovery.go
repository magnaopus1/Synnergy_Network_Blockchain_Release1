package recovery

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
	"strings"
)

// MnemonicService provides methods to generate and recover mnemonic phrases
type MnemonicService struct {
}

// NewMnemonicService initializes and returns a new MnemonicService
func NewMnemonicService() *MnemonicService {
	return &MnemonicService{}
}

// GenerateMnemonic generates a new 12-word mnemonic phrase
func (ms *MnemonicService) GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	return mnemonic, nil
}

// MnemonicToSeed converts a mnemonic phrase to a seed using an optional passphrase
func (ms *MnemonicService) MnemonicToSeed(mnemonic, passphrase string) ([]byte, error) {
	return bip39.NewSeedWithErrorChecking(mnemonic, passphrase)
}

// ValidateMnemonic checks if a given mnemonic phrase is valid
func (ms *MnemonicService) ValidateMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(mnemonic)
}

// EncryptMnemonic encrypts the mnemonic with a passphrase using Argon2
func (ms *MnemonicService) EncryptMnemonic(mnemonic, passphrase string) (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	key := argon2.Key([]byte(passphrase), salt, 3, 32*1024, 4, 32)
	encrypted := make([]byte, len(mnemonic))
	for i := range mnemonic {
		encrypted[i] = mnemonic[i] ^ key[i%len(key)]
	}

	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(encrypted), nil
}

// DecryptMnemonic decrypts the encrypted mnemonic with the passphrase using Argon2
func (ms *MnemonicService) DecryptMnemonic(encrypted, passphrase string) (string, error) {
	parts := strings.Split(encrypted, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted mnemonic format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	encryptedMnemonic, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key := argon2.Key([]byte(passphrase), salt, 3, 32*1024, 4, 32)
	decrypted := make([]byte, len(encryptedMnemonic))
	for i := range encryptedMnemonic {
		decrypted[i] = encryptedMnemonic[i] ^ key[i%len(key)]
	}

	return string(decrypted), nil
}

// RecoverWalletFromMnemonic recovers a wallet from a mnemonic phrase and passphrase
func (ms *MnemonicService) RecoverWalletFromMnemonic(mnemonic, passphrase string) ([]byte, error) {
	if !ms.ValidateMnemonic(mnemonic) {
		return nil, errors.New("invalid mnemonic phrase")
	}
	return ms.MnemonicToSeed(mnemonic, passphrase)
}
