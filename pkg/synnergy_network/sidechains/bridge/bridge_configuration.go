package bridge
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "sync"

    "github.com/synnergy_network/bridge/security_protocols"
    "github.com/synnergy_network/bridge/transfer_logs"
)

// BridgeConfig represents the configuration for the bridge
type BridgeConfig struct {
    NetworkID         string
    SupportedTokens   []string
    MaxTransferAmount float64
    MinTransferAmount float64
    FeePercentage     float64
    EncryptionKey     string
}

// ConfigurationManager manages bridge configurations
type ConfigurationManager struct {
    config *BridgeConfig
    mu     sync.RWMutex
}

// NewConfigurationManager creates a new ConfigurationManager
func NewConfigurationManager() *ConfigurationManager {
    return &ConfigurationManager{
        config: &BridgeConfig{},
    }
}

// LoadConfig loads the configuration from a file
func (cm *ConfigurationManager) LoadConfig(filePath string) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    file, err := os.Open(filePath)
    if err != nil {
        return err
    }
    defer file.Close()

    decoder := json.NewDecoder(file)
    if err := decoder.Decode(cm.config); err != nil {
        return err
    }

    return nil
}

// SaveConfig saves the configuration to a file
func (cm *ConfigurationManager) SaveConfig(filePath string) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    file, err := os.Create(filePath)
    if err != nil {
        return err
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    if err := encoder.Encode(cm.config); err != nil {
        return err
    }

    return nil
}

// UpdateConfig updates the bridge configuration dynamically
func (cm *ConfigurationManager) UpdateConfig(newConfig BridgeConfig) {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    cm.config = &newConfig
    transfer_logs.LogConfigUpdate(newConfig)
}

// GetConfig retrieves the current bridge configuration
func (cm *ConfigurationManager) GetConfig() BridgeConfig {
    cm.mu.RLock()
    defer cm.mu.RUnlock()

    return *cm.config
}

// EncryptConfig encrypts the configuration for secure storage
func (cm *ConfigurationManager) EncryptConfig() (string, error) {
    cm.mu.RLock()
    defer cm.mu.RUnlock()

    key := sha256.Sum256([]byte(cm.config.EncryptionKey))
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return "", err
    }

    configData, err := json.Marshal(cm.config)
    if err != nil {
        return "", err
    }

    ciphertext := make([]byte, aes.BlockSize+len(configData))
    iv := ciphertext[:aes.BlockSize]

    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], configData)

    return fmt.Sprintf("%x", ciphertext), nil
}

// DecryptConfig decrypts the configuration for use
func (cm *ConfigurationManager) DecryptConfig(encryptedConfig string) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    key := sha256.Sum256([]byte(cm.config.EncryptionKey))
    ciphertext, _ := hex.DecodeString(encryptedConfig)
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return err
    }

    if len(ciphertext) < aes.BlockSize {
        return errors.New("ciphertext too short")
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    decryptedData := make([]byte, len(ciphertext))
    copy(decryptedData, ciphertext)

    if err := json.Unmarshal(decryptedData, cm.config); err != nil {
        return err
    }

    return nil
}

// Comprehensive example of security protocols usage
func (cm *ConfigurationManager) ComprehensiveSecurityUsage() {
    // Example of encryption and decryption
    encryptedConfig, _ := cm.EncryptConfig()
    cm.DecryptConfig(encryptedConfig)

    fmt.Println("Original Config:", cm.GetConfig())
    fmt.Println("Encrypted Config:", encryptedConfig)
    fmt.Println("Decrypted Config:", cm.GetConfig())
}

// Example of updating the bridge configuration
func (cm *ConfigurationManager) ExampleUpdateConfig() {
    newConfig := BridgeConfig{
        NetworkID:         "SynnergyNetwork",
        SupportedTokens:   []string{"SYN", "BTC", "ETH"},
        MaxTransferAmount: 1000000.0,
        MinTransferAmount: 0.01,
        FeePercentage:     0.1,
        EncryptionKey:     "mySuperSecureKey",
    }
    cm.UpdateConfig(newConfig)
}

func main() {
    // Create a new ConfigurationManager
    cm := NewConfigurationManager()

    // Load configuration from a file
    err := cm.LoadConfig("config.json")
    if err != nil {
        fmt.Println("Error loading config:", err)
    }

    // Update the configuration dynamically
    cm.ExampleUpdateConfig()

    // Save the updated configuration to a file
    err = cm.SaveConfig("config.json")
    if err != nil {
        fmt.Println("Error saving config:", err)
    }

    // Encrypt and decrypt the configuration for secure storage
    cm.ComprehensiveSecurityUsage()
}
