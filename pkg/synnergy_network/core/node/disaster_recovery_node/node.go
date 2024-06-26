package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// Node represents a Disaster Recovery Node in the Synnergy Network.
type Node struct {
	ID                   string
	BackupFrequency      time.Duration
	BackupLocations      []string
	EncryptionKey        []byte
	PrivateKey           *rsa.PrivateKey
	PublicKey            *rsa.PublicKey
	LastBackupTime       time.Time
	RecoveryDataIntegrity map[string]bool
}

// NewNode creates a new Disaster Recovery Node.
func NewNode(id string, backupFrequency time.Duration, backupLocations []string) (*Node, error) {
	privateKey, publicKey, err := generateRSAKeyPair()
	if err != nil {
		return nil, err
	}

	encryptionKey, err := generateEncryptionKey()
	if err != nil {
		return nil, err
	}

	return &Node{
		ID:                   id,
		BackupFrequency:      backupFrequency,
		BackupLocations:      backupLocations,
		EncryptionKey:        encryptionKey,
		PrivateKey:           privateKey,
		PublicKey:            publicKey,
		RecoveryDataIntegrity: make(map[string]bool),
	}, nil
}

// generateRSAKeyPair generates a new RSA key pair.
func generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// generateEncryptionKey generates a new encryption key using Argon2.
func generateEncryptionKey() ([]byte, error) {
	password := []byte("examplepassword")
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	return key, nil
}

// EncryptData encrypts the given data using AES encryption.
func (n *Node) EncryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(n.EncryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptData decrypts the given data using AES encryption.
func (n *Node) DecryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(n.EncryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// BackupData creates an encrypted backup of the blockchain data.
func (n *Node) BackupData(data []byte) error {
	encryptedData, err := n.EncryptData(data)
	if err != nil {
		return err
	}

	for _, location := range n.BackupLocations {
		err := ioutil.WriteFile(location, encryptedData, 0644)
		if err != nil {
			return err
		}
		n.RecoveryDataIntegrity[location] = true
	}

	n.LastBackupTime = time.Now()
	return nil
}

// RestoreData restores the blockchain data from the backup.
func (n *Node) RestoreData() ([]byte, error) {
	var lastBackup string
	var lastBackupTime time.Time

	for location := range n.RecoveryDataIntegrity {
		info, err := os.Stat(location)
		if err != nil {
			continue
		}

		if info.ModTime().After(lastBackupTime) {
			lastBackupTime = info.ModTime()
			lastBackup = location
		}
	}

	if lastBackup == "" {
		return nil, errors.New("no valid backup found")
	}

	encryptedData, err := ioutil.ReadFile(lastBackup)
	if err != nil {
		return nil, err
	}

	return n.DecryptData(encryptedData)
}

// PeriodicBackup runs periodic backups based on the node's backup frequency.
func (n *Node) PeriodicBackup(data []byte) {
	ticker := time.NewTicker(n.BackupFrequency)
	defer ticker.Stop()

	for range ticker.C {
		err := n.BackupData(data)
		if err != nil {
			log.Printf("Failed to backup data: %v", err)
		} else {
			log.Printf("Backup completed successfully at %s", time.Now())
		}
	}
}

// RunDisasterRecoveryDrill simulates a disaster recovery drill.
func (n *Node) RunDisasterRecoveryDrill() error {
	log.Println("Running disaster recovery drill...")

	backupData := []byte("sample blockchain data for drill")
	err := n.BackupData(backupData)
	if err != nil {
		return err
	}

	restoredData, err := n.RestoreData()
	if err != nil {
		return err
	}

	if string(restoredData) != string(backupData) {
		return errors.New("disaster recovery drill failed: data mismatch")
	}

	log.Println("Disaster recovery drill completed successfully")
	return nil
}

func main() {
	node, err := NewNode("DRNode1", 24*time.Hour, []string{"backup1.dat", "backup2.dat"})
	if err != nil {
		log.Fatalf("Failed to create node: %v", err)
	}

	data := []byte("blockchain state data")
	go node.PeriodicBackup(data)

	err = node.RunDisasterRecoveryDrill()
	if err != nil {
		log.Fatalf("Disaster recovery drill failed: %v", err)
	}

	select {}
}
