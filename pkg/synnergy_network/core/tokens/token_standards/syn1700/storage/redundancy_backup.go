package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/scrypt"
)

// RedundancyBackup handles the backup and redundancy of blockchain data
type RedundancyBackup struct {
	backupDir string
	aesKey    []byte
	salt      []byte
}

// NewRedundancyBackup creates a new instance of RedundancyBackup
func NewRedundancyBackup(backupDir, passphrase string) (*RedundancyBackup, error) {
	// Derive AES key from passphrase using scrypt
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return &RedundancyBackup{
		backupDir: backupDir,
		aesKey:    key,
		salt:      salt,
	}, nil
}

// BackupDatabase creates a backup of the database
func (rb *RedundancyBackup) BackupDatabase(databaseFile string) error {
	// Open the database file
	dbFile, err := os.Open(databaseFile)
	if err != nil {
		return err
	}
	defer dbFile.Close()

	// Create a backup file
	backupFileName := fmt.Sprintf("%s/backup_%s.enc", rb.backupDir, time.Now().Format("20060102_150405"))
	backupFile, err := os.Create(backupFileName)
	if err != nil {
		return err
	}
	defer backupFile.Close()

	// Encrypt and copy the database file to the backup file
	err = rb.encryptAndCopy(dbFile, backupFile)
	if err != nil {
		return err
	}

	log.Printf("Backup created successfully: %s", backupFileName)
	return nil
}

// RestoreDatabase restores the database from a backup file
func (rb *RedundancyBackup) RestoreDatabase(backupFileName, databaseFile string) error {
	// Open the backup file
	backupFile, err := os.Open(backupFileName)
	if err != nil {
		return err
	}
	defer backupFile.Close()

	// Create a new database file
	dbFile, err := os.Create(databaseFile)
	if err != nil {
		return err
	}
	defer dbFile.Close()

	// Decrypt and copy the backup file to the database file
	err = rb.decryptAndCopy(backupFile, dbFile)
	if err != nil {
		return err
	}

	log.Printf("Database restored successfully from backup: %s", backupFileName)
	return nil
}

// encryptAndCopy encrypts the input file and writes to the output file
func (rb *RedundancyBackup) encryptAndCopy(src io.Reader, dst io.Writer) error {
	block, err := aes.NewCipher(rb.aesKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return err
	}

	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		ciphertext := gcm.Seal(nonce, nonce, buf[:n], nil)
		encoded := base64.StdEncoding.EncodeToString(ciphertext)
		_, err = dst.Write([]byte(encoded))
		if err != nil {
			return err
		}
	}

	return nil
}

// decryptAndCopy decrypts the input file and writes to the output file
func (rb *RedundancyBackup) decryptAndCopy(src io.Reader, dst io.Writer) error {
	block, err := aes.NewCipher(rb.aesKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		data, err := base64.StdEncoding.DecodeString(string(buf[:n]))
		if err != nil {
			return err
		}

		if len(data) < nonceSize {
			return errors.New("ciphertext too short")
		}

		nonce, ciphertext := data[:nonceSize], data[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return err
		}

		_, err = dst.Write(plaintext)
		if err != nil {
			return err
		}
	}

	return nil
}

// ListBackups lists all backup files
func (rb *RedundancyBackup) ListBackups() ([]string, error) {
	files, err := os.ReadDir(rb.backupDir)
	if err != nil {
		return nil, err
	}

	var backups []string
	for _, file := range files {
		if !file.IsDir() && file.Name() != ".DS_Store" {
			backups = append(backups, file.Name())
		}
	}

	return backups, nil
}

// DeleteOldBackups deletes backup files older than the specified duration
func (rb *RedundancyBackup) DeleteOldBackups(olderThan time.Duration) error {
	files, err := os.ReadDir(rb.backupDir)
	if err != nil {
		return err
	}

	now := time.Now()
	for _, file := range files {
		if file.IsDir() || file.Name() == ".DS_Store" {
			continue
		}

		info, err := file.Info()
		if err != nil {
			return err
		}

		if now.Sub(info.ModTime()) > olderThan {
			err := os.Remove(fmt.Sprintf("%s/%s", rb.backupDir, file.Name()))
			if err != nil {
				return err
			}
			log.Printf("Deleted old backup: %s", file.Name())
		}
	}

	return nil
}
