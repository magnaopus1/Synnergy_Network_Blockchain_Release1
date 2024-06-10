package crypto

import (
    "crypto"
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "io"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

// GenerateKeyPair generates an RSA or ECDSA key pair for signing transactions.
func GenerateKeyPair(useRSA bool) (crypto.PrivateKey, crypto.PublicKey, error) {
    if useRSA {
        // Generate RSA keys
        private, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
            return nil, nil, err
        }
        return private, &private.PublicKey, nil
    }

    // Generate ECDSA keys
    private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, nil, err
    }
    return private, &private.PublicKey, nil
}

// HashData generates a SHA-256 hash of the data.
func HashData(data []byte) string {
    hash := sha256.Sum256(data)
    return string(hash[:])
}

// SignData signs data using the private key.
func SignData(priv crypto.PrivateKey, data []byte) ([]byte, error) {
    var hash []byte
    switch priv := priv.(type) {
    case *rsa.PrivateKey:
        hasher := sha256.New()
        if _, err := io.Copy(hasher, bytes.NewReader(data)); err != nil {
            return nil, err
        }
        hash = hasher.Sum(nil)
        return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash)
    case *ecdsa.PrivateKey:
        hash = sha256.Sum256(data)
        r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
        if err != nil {
            return nil, err
        }
        signature := r.Bytes()
        signature = append(signature, s.Bytes()...)
        return signature, nil
    default:
        return nil, errors.New("unsupported key type")
    }
}

// VerifySignature verifies a signature using the public key.
func VerifySignature(pub crypto.PublicKey, data, signature []byte) bool {
    switch pub := pub.(type) {
    case *rsa.PublicKey:
        hasher := sha256.New()
        hasher.Write(data)
        return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hasher.Sum(nil), signature) == nil
    case *ecdsa.PublicKey:
        r, s := new(big.Int), new(big.Int)
        r.SetBytes(signature[:len(signature)/2])
        s.SetBytes(signature[len(signature)/2:])
        hash := sha256.Sum256(data)
        return ecdsa.Verify(pub, hash[:], r, s)
    default:
        return false
    }
}

// EncryptData encrypts data using AES with a key derived from the passphrase using Argon2.
func EncryptData(data, passphrase []byte) ([]byte, error) {
    salt := []byte("use a better salt here")
    key := argon2.IDKey(passphrase, salt, 1, 64*1024, 4, 32)
    
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return ciphertext, nil
}

// DecryptData decrypts data using AES and a key derived from the passphrase.
func DecryptData(data, passphrase []byte) ([]byte, error) {
    salt := []byte("use a better salt here")
    key := argon2.IDKey(passphrase, salt, 1, 64*1024, 4, 32)

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    if len(data) < gcm.NonceSize() {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

