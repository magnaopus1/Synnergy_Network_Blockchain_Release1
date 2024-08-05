package config_management

import (
    "fmt"
    "os/exec"
    "log"
    "io/ioutil"
    "encoding/json"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "io"
)

// Config structure for Ansible integration
type AnsibleConfig struct {
    PlaybookPath string `json:"playbook_path"`
    Inventory    string `json:"inventory"`
    Variables    map[string]string `json:"variables"`
    EncryptionKey string `json:"encryption_key"`
}

// LoadConfig loads the Ansible configuration from a JSON file
func LoadConfig(configPath string) (*AnsibleConfig, error) {
    data, err := ioutil.ReadFile(configPath)
    if err != nil {
        return nil, err
    }
    var config AnsibleConfig
    err = json.Unmarshal(data, &config)
    if err != nil {
        return nil, err
    }
    return &config, nil
}

// Encrypt encrypts the given plaintext using AES encryption
func Encrypt(plaintext, key string) (string, error) {
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, aesGCM.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using AES encryption
func Decrypt(ciphertext, key string) (string, error) {
    data, err := base64.StdEncoding.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonceSize := aesGCM.NonceSize()
    if len(data) < nonceSize {
        return "", errors.New("ciphertext too short")
    }
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(plaintext), nil
}

// ExecutePlaybook executes the specified Ansible playbook
func ExecutePlaybook(config *AnsibleConfig) error {
    cmd := exec.Command("ansible-playbook", "-i", config.Inventory, config.PlaybookPath)
    for k, v := range config.Variables {
        cmd.Args = append(cmd.Args, fmt.Sprintf("-e \"%s=%s\"", k, v))
    }
    output, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("ansible-playbook execution failed: %v, output: %s", err, string(output))
    }
    log.Printf("ansible-playbook executed successfully: %s", string(output))
    return nil
}

// UpdateNodeConfiguration updates the configuration of nodes using Ansible
func UpdateNodeConfiguration(configPath string) error {
    config, err := LoadConfig(configPath)
    if err != nil {
        return err
    }
    return ExecutePlaybook(config)
}

