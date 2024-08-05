package config_management

import (
	"fmt"
	"log"
	"os/exec"
	"time"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// ChefIntegration is a struct that manages the integration with Chef for automated configuration management
type ChefIntegration struct {
	chefServerURL    string
	chefClientKey    string
	chefNodeName     string
	encryptedKey     []byte
	encryptionKey    []byte
}

// NewChefIntegration initializes a new instance of ChefIntegration
func NewChefIntegration(serverURL, clientKey, nodeName string, encryptionKey []byte) *ChefIntegration {
	return &ChefIntegration{
		chefServerURL: serverURL,
		chefClientKey: clientKey,
		chefNodeName:  nodeName,
		encryptionKey: encryptionKey,
	}
}

// EncryptData encrypts the given data using AES
func (ci *ChefIntegration) EncryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ci.encryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptData decrypts the given data using AES
func (ci *ChefIntegration) DecryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ci.encryptionKey)
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

// UploadCookbook uploads a Chef cookbook to the Chef server
func (ci *ChefIntegration) UploadCookbook(cookbookPath string) error {
	cmd := exec.Command("knife", "cookbook", "upload", cookbookPath, "--server-url", ci.chefServerURL, "--key", ci.chefClientKey, "--node-name", ci.chefNodeName)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Failed to upload cookbook: %s", err)
		return err
	}
	fmt.Printf("Cookbook uploaded successfully: %s", out.String())
	return nil
}

// UpdateNodeConfiguration updates the configuration of a Chef node
func (ci *ChefIntegration) UpdateNodeConfiguration(nodeConfigPath string) error {
	cmd := exec.Command("knife", "node", "edit", ci.chefNodeName, "--server-url", ci.chefServerURL, "--key", ci.chefClientKey, "--node-name", ci.chefNodeName, "--config-file", nodeConfigPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Failed to update node configuration: %s", err)
		return err
	}
	fmt.Printf("Node configuration updated successfully: %s", out.String())
	return nil
}

// ScheduleConfigurationUpdate schedules a configuration update at a specific time
func (ci *ChefIntegration) ScheduleConfigurationUpdate(cookbookPath, nodeConfigPath string, updateTime time.Time) {
	duration := time.Until(updateTime)
	if duration < 0 {
		log.Fatalf("Scheduled time is in the past")
		return
	}
	time.AfterFunc(duration, func() {
		err := ci.UploadCookbook(cookbookPath)
		if err != nil {
			log.Fatalf("Failed to upload cookbook: %s", err)
		}
		err = ci.UpdateNodeConfiguration(nodeConfigPath)
		if err != nil {
			log.Fatalf("Failed to update node configuration: %s", err)
		}
	})
}

// main function is excluded as per the instructions
