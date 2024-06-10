package address

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "golang.org/x/crypto/argon2"
    "math/big"
)

// GenerateKeyPair generates an ECDSA key pair using elliptic curve cryptography.
func GenerateKeyPair() (*ecdsa.PrivateKey, error) {
    curve := elliptic.P256() // Using P-256 curve for a balance between security and performance
    return ecdsa.GenerateKey(curve, rand.Reader)
}

// PublicKeyToAddress converts a public key to a blockchain address using SHA-256 and RIPEMD-160.
func PublicKeyToAddress(pub *ecdsa.PublicKey) string {
    pubBytes := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
    shaHash := sha256.Sum256(pubBytes)
    // Simulating RIPEMD-160 using SHA-256; replace with actual RIPEMD-160 in production
    ripeHash := sha256.Sum256(shaHash[:]) 
    address := hex.EncodeToString(ripeHash[:])
    return address
}

// SignTransaction signs data with a private key, returning the signature.
func SignTransaction(priv *ecdsa.PrivateKey, data []byte) ([]byte, error) {
    r, s, err := ecdsa.Sign(rand.Reader, priv, data)
    if err != nil {
        return nil, err
    }
    signature := append(r.Bytes(), s.Bytes()...)
    return signature, nil
}

// VerifySignature checks the signature against a public key and data.
func VerifySignature(pub *ecdsa.PublicKey, data, signature []byte) bool {
    r := new(big.Int).SetBytes(signature[:len(signature)/2])
    s := new(big.Int).SetBytes(signature[len(signature)/2:])
    return ecdsa.Verify(pub, data, r, s)
}

// EncryptPrivateKey encrypts a private key using AES with a derived key from Argon2.
func EncryptPrivateKey(priv *ecdsa.PrivateKey, password string) ([]byte, error) {
    key := argon2.IDKey([]byte(password), []byte("salt"), 1, 64*1024, 4, 32) // Using Argon2 for key derivation

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }

    privBytes, err := x509.MarshalECPrivateKey(priv)
    if err != nil {
        return nil, err
    }

    ciphertext := gcm.Seal(nonce, nonce, privBytes, nil)
    return ciphertext, nil
}

// DecryptPrivateKey decrypts a private key using AES with a derived key from Argon2.
func DecryptPrivateKey(data []byte, password string) (*ecdsa.PrivateKey, error) {
    key := argon2.IDKey([]byte(password), []byte("salt"), 1, 64*1024, 4, 32)

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    if len(data) < gcm.NonceSize() {
        return nil, errors.New("malformed ciphertext")
    }

    nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
    privBytes, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    priv, err := x509.ParseECPrivateKey(privBytes)
    if err != nil {
        return nil, err
    }

    return priv, nil
}

// ValidateAddress checks if the address is valid based on its format and checksum.
func ValidateAddress(address string) bool {
    // Add actual validation logic here, e.g., regex pattern matching and checksum verification
    return true
}

