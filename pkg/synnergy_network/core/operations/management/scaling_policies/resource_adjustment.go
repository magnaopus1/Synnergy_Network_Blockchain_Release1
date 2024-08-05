package scaling_policies

import (
    "sync"
    "time"
    "context"
    "log"
    "math"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
    "encoding/base64"
    "golang.org/x/crypto/scrypt"
    "golang.org/x/crypto/argon2"
)

// ResourceAllocation defines the structure for resource allocation policies
type ResourceAllocation struct {
    MinNodes            int
    MaxNodes            int
    CurrentNodes        int
    ScalingFactor       float64
    UsageThreshold      float64
    CheckInterval       time.Duration
    ResourceLock        sync.Mutex
    ScalingUpPolicy     func(currentNodes, maxNodes int) int
    ScalingDownPolicy   func(currentNodes, minNodes int) int
}

// NewResourceAllocation creates a new instance of ResourceAllocation
func NewResourceAllocation(minNodes, maxNodes int, scalingFactor, usageThreshold float64, checkInterval time.Duration) *ResourceAllocation {
    return &ResourceAllocation{
        MinNodes:       minNodes,
        MaxNodes:       maxNodes,
        CurrentNodes:   minNodes,
        ScalingFactor:  scalingFactor,
        UsageThreshold: usageThreshold,
        CheckInterval:  checkInterval,
        ScalingUpPolicy: defaultScalingUpPolicy,
        ScalingDownPolicy: defaultScalingDownPolicy,
    }
}

// defaultScalingUpPolicy defines the default policy for scaling up resources
func defaultScalingUpPolicy(currentNodes, maxNodes int) int {
    if currentNodes < maxNodes {
        return int(math.Min(float64(currentNodes+1), float64(maxNodes)))
    }
    return currentNodes
}

// defaultScalingDownPolicy defines the default policy for scaling down resources
func defaultScalingDownPolicy(currentNodes, minNodes int) int {
    if currentNodes > minNodes {
        return int(math.Max(float64(currentNodes-1), float64(minNodes)))
    }
    return currentNodes
}

// AdjustResources adjusts the number of resources based on current usage
func (ra *ResourceAllocation) AdjustResources(currentUsage float64) {
    ra.ResourceLock.Lock()
    defer ra.ResourceLock.Unlock()

    if currentUsage > ra.UsageThreshold {
        ra.CurrentNodes = ra.ScalingUpPolicy(ra.CurrentNodes, ra.MaxNodes)
    } else if currentUsage < ra.UsageThreshold {
        ra.CurrentNodes = ra.ScalingDownPolicy(ra.CurrentNodes, ra.MinNodes)
    }
    log.Printf("Adjusted resources to %d nodes based on current usage: %f", ra.CurrentNodes, currentUsage)
}

// StartMonitoring starts the monitoring process to adjust resources based on usage
func (ra *ResourceAllocation) StartMonitoring(ctx context.Context, usageProvider func() float64) {
    ticker := time.NewTicker(ra.CheckInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            currentUsage := usageProvider()
            ra.AdjustResources(currentUsage)
        case <-ctx.Done():
            log.Println("Stopping resource monitoring")
            return
        }
    }
}

// Encryption Utilities

// Encrypt encrypts plaintext using AES with a given key
func Encrypt(key, plaintext string) (string, error) {
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }

    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

    return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES with a given key
func Decrypt(key, cryptoText string) (string, error) {
    ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }

    if len(ciphertext) < aes.BlockSize {
        return "", err
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    return string(ciphertext), nil
}

// GenerateHash generates a secure hash using Argon2
func GenerateHash(password, salt string) string {
    hash := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
    return base64.RawStdEncoding.EncodeToString(hash)
}

// GenerateScryptHash generates a secure hash using Scrypt
func GenerateScryptHash(password, salt string) (string, error) {
    hash, err := scrypt.Key([]byte(password), []byte(salt), 32768, 8, 1, 32)
    if err != nil {
        return "", err
    }
    return base64.RawStdEncoding.EncodeToString(hash), nil
}

// Utility function to generate a random salt
func GenerateSalt(size int) (string, error) {
    salt := make([]byte, size)
    _, err := rand.Read(salt)
    if err != nil {
        return "", err
    }
    return base64.RawStdEncoding.EncodeToString(salt), nil
}
