package data_protection

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "io/ioutil"
)

// KeyManager handles cryptographic keys for secure data operations.
type KeyManager struct {
    rsaPrivateKey *rsa.PrivateKey
    ecdsaPrivateKey *ecdsa.PrivateKey
}

// NewKeyManager initializes key management with specified key type (RSA or ECC).
func NewKeyManager(useECC bool) (*KeyManager, error) {
    if useECC {
        privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
        if err != nil {
            return nil, err
        }
        return &KeyManager{ecdsaPrivateKey: privateKey}, nil
    }

    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, err
    }
    return &KeyManager{rsaPrivateKey: privateKey}, nil
}

// ExportPublicKey exports the public key in PEM format.
func (km *KeyManager) ExportPublicKey() ([]byte, error) {
    var publicKeyBytes []byte
    var err error

    if km.rsaPrivateKey != nil {
        publicKeyBytes, err = x509.MarshalPKIXPublicKey(&km.rsaPrivateKey.PublicKey)
    } else if km.ecdsaPrivateKey != nil {
        publicKeyBytes, err = x509.MarshalPKIXPublicKey(&km.ecdsaPrivateKey.PublicKey)
    } else {
        return nil, errors.New("no private key initialized")
    }

    if err != nil {
        return nil, err
    }

    publicKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyBytes,
    })

    return publicKeyPEM, nil
}

// EncryptDataWithPublicKey encrypts data using the public key (RSA or ECC based on initialization).
func (km *KeyManager) EncryptDataWithPublicKey(data []byte) ([]byte, error) {
    if km.rsaPrivateKey != nil {
        return rsa.EncryptPKCS1v15(rand.Reader, &km.rsaPrivateKey.PublicKey, data)
    } else if km.ecdsaPrivateKey != nil {
        return nil, errors.New("ECC encryption not directly supported, use hybrid approach")
    }
    return nil, errors.New("no valid encryption method available")
}

// SavePrivateKey saves the private key to a secure storage.
func (km *KeyManager) SavePrivateKey(filePath string) error {
    var privateKeyBytes []byte
    var err error

    if km.rsaPrivateKey != nil {
        privateKeyBytes = x509.MarshalPKCS1PrivateKey(km.rsaPrivateKey)
    } else if km.ecdsaPrivateKey != nil {
        privateKeyBytes, err = x509.MarshalECPrivateKey(km.ecdsaPrivateKey)
        if err != nil {
            return err
        }
    } else {
        return errors.New("no private key initialized")
    }

    privateKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: privateKeyBytes,
    })

    return ioutil.WriteFile(filePath, privateKeyPEM, 0600) // Save with secure permissions
}

// Implement additional functionalities as required for key lifecycle management, secure storage, etc.
