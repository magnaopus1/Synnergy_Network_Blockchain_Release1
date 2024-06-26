package encryption

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "os"
)

// RSAEncryptionManager handles RSA operations for the Synnergy Network.
type RSAEncryptionManager struct {
    privateKey *rsa.PrivateKey
    publicKey  *rsa.PublicKey
}

// GenerateRSAKeys generates a new RSA key pair and stores them in the specified files.
func GenerateRSAKeys(privateKeyPath, publicKeyPath string, keySize int) error {
    privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
    if err != nil {
        return err
    }

    // Save the private key
    privFile, err := os.Create(privateKeyPath)
    if err != nil {
        return err
    }
    defer privFile.Close()

    privPEM := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    }
    if err := pem.Encode(privFile, privPEM); err != nil {
        return err
    }

    // Save the public key
    pubFile, err := os.Create(publicKeyPath)
    if err != nil {
        return err
    }
    defer pubFile.Close()

    pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
    if err != nil {
        return err
    }

    pubPEM := &pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: pubASN1,
    }
    if err := pem.Encode(pubFile, pubPEM); err != nil {
        return err
    }

    return nil
}

// Encrypt encrypts data using the public key.
func (r *RSAEncryptionManager) Encrypt(data []byte) ([]byte, error) {
    return rsa.EncryptOAEP(sha256.New(), rand.Reader, r.publicKey, data, nil)
}

// Decrypt decrypts data using the private key.
func (r *RSAEncryptionManager) Decrypt(ciphertext []byte) ([]byte, error) {
    return rsa.DecryptOAEP(sha256.New(), rand.Reader, r.privateKey, ciphertext, nil)
}

// Sign creates a signature using the private key.
func (r *RSAEncryptionManager) Sign(data []byte) ([]byte, error) {
    hash := sha256.Sum256(data)
    return rsa.SignPKCS1v15(rand.Reader, r.privateKey, crypto.SHA256, hash[:])
}

// VerifySignature checks the signature using the public key.
func (r *RSAEncryption, signature, data []byte) bool {
    hash := sha256.Sum256(data)
    err := rsa.VerifyPKCS1v15(r.publicKey, crypto.SHA256, hash[:], signature)
    return err == nil
}

// NewRSAEncryptionManager creates a new instance of RSAEncryptionManager with keys loaded from files.
func NewRSAEncryptionManager(privateKeyPath, publicKeyPath string) (*RSAEncryptionManager, error) {
    privateKey, err := loadPrivateKey(privateKeyTemplate)
    if err != nil {
        return nil, err
    }
    publicKey, err := loadPublicKey(publicKeyPath)
    if err != nil {
        return nil, err
    }

    return &RSAEncryptionManager{
        privateKey: privateKey,
        publicKey:  publicKey,
    }, nil
}
