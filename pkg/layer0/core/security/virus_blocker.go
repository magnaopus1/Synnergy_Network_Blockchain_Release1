package security

import (
    "bufio"
    "fmt"
    "os"
    "strings"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

const (
    Salt         = "your-unique-salt"
    KeyLength    = 32
    ScryptN      = 16384
    ScryptR      = 8
    ScryptP      = 1
    ArgonTime    = 1
    ArgonMemory  = 64 * 1024
    ArgonThreads = 4
)

// VirusBlockerConfig holds configuration for the virus blocker
type VirusBlockerConfig struct {
    Blocklist []string
}

// VirusBlocker provides methods to block malicious files
type VirusBlocker struct {
    Config VirusBlockerConfig
}

// NewVirusBlocker initializes a new VirusBlocker with default settings
func NewVirusBlocker() *VirusBlocker {
    return &VirusBlocker{
        Config: VirusBlockerConfig{
            Blocklist: []string{"malware.exe", "ransomware.exe"},
        },
    }
}

// BlockFile checks if a file is in the blocklist and prevents its execution
func (vb *VirusBlocker) BlockFile(filePath string) bool {
    fileName := strings.ToLower(filepath.Base(filePath))
    for _, banned := range vb.Config.Blocklist {
        if strings.Contains(fileName, banned) {
            fmt.Printf("Blocked: %s is on the blocklist.\n", fileName)
            return true
        }
    }
    return false
}

// EncryptData uses Argon2 for data encryption
func EncryptData(data []byte) ([]byte, error) {
    salt := []byte(Salt)
    return argon2.IDKey(data, salt, ArgonTime, ArgonMemory, ArgonThreads, KeyLength), nil
}

// DecryptData uses Scrypt for secure decryption
func DecryptData(encryptedData, salt []byte) ([]byte, error) {
    return scrypt.Key(encryptedData, salt, ScryptN, ScryptR, ScryptP, KeyLength)
}

// main function to demonstrate the usage of VirusBlocker
func main() {
    vb := NewVirusBlocker()
    filesToCheck := []string{"/path/to/malware.exe", "/path/to/validprogram.exe"}

    for _, file := range filesToCheck {
        if vb.BlockFile(file) {
            fmt.Println("Action Taken: The file has been blocked.")
        } else {
            fmt.Println("File is safe to use:", file)
        }
    }
}
