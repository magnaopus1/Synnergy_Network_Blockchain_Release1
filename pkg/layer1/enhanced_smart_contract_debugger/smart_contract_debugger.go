package enhancedsmartcontractdebugger

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"os"

	"github.com/synthron_blockchain/crypto"
)

// Debugger holds configurations for the smart contract debugger.
type Debugger struct {
	LogFilePath string
	EncryptionKey []byte
}

// NewDebugger creates a new Debugger instance with specified encryption key and log file path.
func NewDebugger(key []byte, logFilePath string) *Debugger {
	return &Debugger{
		EncryptionKey: key,
		LogFilePath: logFilePath,
	}
}

// DebugContract simulates the debugging of a smart contract's execution.
func (d *Debugger) DebugContract(contractCode string) (result string, err error) {
	// Simulate checking the contract code for errors
	if contractCode == "" {
		return "", errors.New("no contract code provided")
	}

	// Simulate contract execution and logging
	logMessage := "Debugging contract: successful execution"
	d.encryptAndLog(logMessage)

	return "Execution successful", nil
}

// encryptAndLog encrypts and logs message to a file.
func (d *Debugger) encryptAndLog(message string) error {
	// Encrypt the log message
	encryptedMessage, err := d.encrypt([]byte(message))
	if err != nil {
		return err
	}

	// Write the encrypted log to file
	return ioutil.WriteFile(d.LogFilePath, encryptedMessage, 0644)
}

// encrypt performs AES encryption on the provided data.
func (d *Debugger) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(d.EncryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := os.Read(nonce, nonce); err != nil {
		return nil, err
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

// ReadLogs reads and decrypts the logs from the file.
func (d *Debugger) ReadLogs() (string, error) {
	encryptedData, err := ioutil.ReadFile(d.LogFilePath)
	if err != nil {
		return "", err
	}

	decryptedData, err := d.decrypt(encryptedData)
	if err != nil {
		return "", err
	}

	return string(decryptedData), nil
}

// decrypt performs AES decryption on the provided data.
func (d *Debugger) decrypt(encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(d.EncryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}
