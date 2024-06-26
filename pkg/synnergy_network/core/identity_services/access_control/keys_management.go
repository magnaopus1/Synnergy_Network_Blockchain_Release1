package identity_services

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "encoding/hex"
    "log"
    "sync"

    "golang.org/x/crypto/argon2"
)

// KeyManager handles the lifecycle of cryptographic keys used within the access control system.
type KeyManager struct {
    privateKeys map[string]*ecdsa.PrivateKey
    mutex       sync.RWMutex
}

// NewKeyManager creates a new instance of KeyManager.
func NewKeyManager() *KeyManager {
    return &KeyManager{
        privateKeys: make(map[string]*ecdsa.PrivateKey),
    }
}

// GenerateKey generates a new ECDSA private key for a user and stores it securely.
func (km *KeyManager) GenerateKey(userID string) (string, error) {
    km.mutex.Lock()
    defer km.mutex.Unlock()

    if _, exists := km.privateKeys[userID]; exists {
        return "", errors.New("key already exists for this user")
    }

    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return "", err
    }

    km.privateKeys[userID] = privateKey

    publicKeyBytes := elliptic.Marshal(privateKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
    return hex.EncodeToString(publicKeyBytes), nil
}

// RetrievePublicKey retrieves the public key for a given user's private key.
func (km *KeyManager) RetrievePublicKey(userID string) (string, error) {
    km.mutex.RLock()
    defer km.mutex.RUnlock()

    privateKey, exists := km.privateKeys[userID]
    if !exists {
        return "", errors.New("no key found for this user")
    }

    publicKeyBytes := elliptic.Marshal(privateKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
    return hex.EncodeToString(publicKeyBytes), nil
}

// SignData signs data using a user's private key.
func (km *KeyManager) SignData(userID string, data []byte) (string, error) {
    km.mutex.RLock()
    privateKey, exists := km.privateKeys[userID]
    km.mutex.RUnlock()

    if !exists {
        return "", errors.New("no private key found for user")
    }

    hash := argon2.IDKey(data, []byte(userID), 1, 64*1024, 4, 32)
    r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
    if err != nil {
        return "", err
    }

    signature := r.Bytes()
    signature = append(signature, s.Bytes()...)
    return hex.EncodeToString(signature), nil
}

func main() {
    keyManager := NewKeyManager()
    userID := "user123"

    // Generate a new key for the user
    publicKey, err := keyManager.GenerateKey(userID)
    if err != nil {
        log.Fatal("Failed to generate key:", err)
    }
    log.Println("Public Key:", publicKey)

    // Example data to be signed
    data := []byte("Important transaction data")
    signature, err := keyManager.SignData(userID, data)
    if err != nil {
        log.Fatal("Failed to sign data:", err)
    }
    log.Println("Signature:", signature)
}
