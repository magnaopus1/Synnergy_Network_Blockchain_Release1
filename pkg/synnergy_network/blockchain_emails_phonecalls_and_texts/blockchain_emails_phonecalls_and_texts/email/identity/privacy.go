package identity

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/base64"
    "errors"
    "io"
    "golang.org/x/crypto/argon2"
)

// EncryptionManager handles encryption and decryption operations
type EncryptionManager struct {
    key []byte
}

// NewEncryptionManager creates a new EncryptionManager with a given password
func NewEncryptionManager(password string) *EncryptionManager {
    salt := make([]byte, 16)
    _, err := io.ReadFull(rand.Reader, salt)
    if err != nil {
        panic(err)
    }

    key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
    return &EncryptionManager{key: key}
}

// Encrypt encrypts plaintext using AES-GCM
func (em *EncryptionManager) Encrypt(plaintext string) (string, error) {
    block, err := aes.NewCipher(em.key)
    if err != nil {
        return "", err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, aesGCM.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
    return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-GCM
func (em *EncryptionManager) Decrypt(ciphertext string) (string, error) {
    data, err := base64.URLEncoding.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(em.key)
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

// Identity represents a user identity
type Identity struct {
    Name  string
    Email string
}

// IdentityManager manages identities and their privacy
type IdentityManager struct {
    encryptionManager *EncryptionManager
    identities        map[string]Identity
}

// NewIdentityManager creates a new IdentityManager
func NewIdentityManager(password string) *IdentityManager {
    return &IdentityManager{
        encryptionManager: NewEncryptionManager(password),
        identities:        make(map[string]Identity),
    }
}

// AddIdentity adds a new identity to the manager
func (im *IdentityManager) AddIdentity(name, email string) error {
    encryptedName, err := im.encryptionManager.Encrypt(name)
    if err != nil {
        return err
    }

    encryptedEmail, err := im.encryptionManager.Encrypt(email)
    if err != nil {
        return err
    }

    im.identities[encryptedName] = Identity{Name: encryptedName, Email: encryptedEmail}
    return nil
}

// GetIdentity retrieves an identity by name
func (im *IdentityManager) GetIdentity(name string) (Identity, error) {
    encryptedName, err := im.encryptionManager.Encrypt(name)
    if err != nil {
        return Identity{}, err
    }

    identity, exists := im.identities[encryptedName]
    if !exists {
        return Identity{}, errors.New("identity not found")
    }

    decryptedName, err := im.encryptionManager.Decrypt(identity.Name)
    if err != nil {
        return Identity{}, err
    }

    decryptedEmail, err := im.encryptionManager.Decrypt(identity.Email)
    if err != nil {
        return Identity{}, err
    }

    return Identity{Name: decryptedName, Email: decryptedEmail}, nil
}

// RemoveIdentity removes an identity from the manager
func (im *IdentityManager) RemoveIdentity(name string) error {
    encryptedName, err := im.encryptionManager.Encrypt(name)
    if err != nil {
        return err
    }

    _, exists := im.identities[encryptedName]
    if !exists {
        return errors.New("identity not found")
    }

    delete(im.identities, encryptedName)
    return nil
}

// VerifyIdentity verifies if the provided name and email match an existing identity
func (im *IdentityManager) VerifyIdentity(name, email string) (bool, error) {
    encryptedName, err := im.encryptionManager.Encrypt(name)
    if err != nil {
        return false, err
    }

    identity, exists := im.identities[encryptedName]
    if !exists {
        return false, nil
    }

    encryptedEmail, err := im.encryptionManager.Encrypt(email)
    if err != nil {
        return false, err
    }

    if subtle.ConstantTimeCompare([]byte(identity.Email), []byte(encryptedEmail)) == 1 {
        return true, nil
    }

    return false, nil
}
