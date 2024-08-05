package governance_education

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "sync"

    "golang.org/x/crypto/scrypt"
)

// EducationalResource represents an educational resource in the governance system.
type EducationalResource struct {
    ID          string
    Title       string
    Content     string
    Encrypted   bool
    EncryptionKey string
}

var resources = make(map[string]EducationalResource)
var mutex = &sync.Mutex{}

// AddResource adds a new educational resource to the system.
func AddResource(title, content, password string, encrypt bool) (string, error) {
    mutex.Lock()
    defer mutex.Unlock()

    id := generateID()
    resource := EducationalResource{
        ID:    id,
        Title: title,
        Content: content,
    }

    if encrypt {
        encryptedContent, encryptionKey, err := encryptContent(content, password)
        if err != nil {
            return "", err
        }
        resource.Content = encryptedContent
        resource.Encrypted = true
        resource.EncryptionKey = encryptionKey
    }

    resources[id] = resource
    return id, nil
}

// GetResource retrieves an educational resource by its ID.
func GetResource(id, password string) (EducationalResource, error) {
    mutex.Lock()
    defer mutex.Unlock()

    resource, exists := resources[id]
    if !exists {
        return EducationalResource{}, fmt.Errorf("resource not found")
    }

    if resource.Encrypted {
        decryptedContent, err := decryptContent(resource.Content, resource.EncryptionKey, password)
        if err != nil {
            return EducationalResource{}, err
        }
        resource.Content = decryptedContent
    }

    return resource, nil
}

// ListResources lists all educational resources.
func ListResources() []EducationalResource {
    mutex.Lock()
    defer mutex.Unlock()

    result := make([]EducationalResource, 0, len(resources))
    for _, resource := range resources {
        result = append(result, resource)
    }

    return result
}

// SaveResources saves all resources to a file.
func SaveResources(filePath string) error {
    mutex.Lock()
    defer mutex.Unlock()

    data, err := json.Marshal(resources)
    if err != nil {
        return err
    }

    return os.WriteFile(filePath, data, 0644)
}

// LoadResources loads resources from a file.
func LoadResources(filePath string) error {
    mutex.Lock()
    defer mutex.Unlock()

    data, err := os.ReadFile(filePath)
    if err != nil {
        return err
    }

    return json.Unmarshal(data, &resources)
}

// generateID generates a unique ID for a new resource.
func generateID() string {
    return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d", rand.Int63()))))
}

// encryptContent encrypts the content using AES and scrypt for key derivation.
func encryptContent(content, password string) (string, string, error) {
    salt := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return "", "", err
    }

    key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
    if err != nil {
        return "", "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", "", err
    }

    ciphertext := gcm.Seal(nonce, nonce, []byte(content), nil)
    encryptionKey := fmt.Sprintf("%x", salt)
    return fmt.Sprintf("%x", ciphertext), encryptionKey, nil
}

// decryptContent decrypts the content using AES and scrypt for key derivation.
func decryptContent(encryptedContent, encryptionKey, password string) (string, error) {
    salt, err := hexToBytes(encryptionKey)
    if err != nil {
        return "", err
    }

    key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    ciphertext, err := hexToBytes(encryptedContent)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return "", fmt.Errorf("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    content, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(content), nil
}

// hexToBytes converts a hex string to a byte slice.
func hexToBytes(hexStr string) ([]byte, error) {
    data := make([]byte, len(hexStr)/2)
    _, err := fmt.Sscanf(hexStr, "%x", &data)
    if err != nil {
        return nil, err
    }
    return data, nil
}
