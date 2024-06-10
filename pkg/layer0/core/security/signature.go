package security

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
    "math/big"
)

const (
    Salt       = "secure-salt-here"
    KeyLength  = 32
)

// Signature represents the components of a digital signature.
type Signature struct {
    R, S *big.Int
}

// GenerateKeys generates a new public-private key pair for signing.
func GenerateKeys() (*ecdsa.PrivateKey, error) {
    curve := elliptic.P256() // Using P-256 curve for ECDSA
    return ecdsa.GenerateKey(curve, rand.Reader)
}

// SignData creates a signature from the given data using the private key.
func SignData(privateKey *ecdsa.PrivateKey, data []byte) (*Signature, error) {
    hash := sha256.Sum256(data)
    r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
    if err != nil {
        return nil, err
    }
    return &Signature{R: r, S: s}, nil
}

// VerifySignature checks the signature against the data and public key to ensure integrity.
func VerifySignature(publicKey *ecdsa.PublicKey, signature *Signature, data []byte) bool {
    hash := sha256.Sum256(data)
    return ecdsa.Verify(publicKey, hash[:], signature.R, signature.S)
}

// EncryptData uses Argon2 to encrypt data securely.
func EncryptData(data string) string {
    salt := []byte(Salt)
    hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, KeyLength)
    return hex.EncodeToString(hash)
}

// DecryptData uses Scrypt to simulate decryption process (one-way in reality).
func DecryptData(data string) ([]byte, error) {
    salt := []byte(Salt)
    dataBytes, err := hex.DecodeString(data)
    if err != nil {
        return nil, err
    }
    return scrypt.Key(dataBytes, salt, 16384, 8, 1, KeyLength)
}

// Example usage of the cryptographic functions
func main() {
    // Generate a key pair
    privKey, err := GenerateKeys()
    if err != nil {
        panic(err)
    }
    publicKey := &privKey.PublicKey

    // Sign data
    data := "Sensitive blockchain transaction"
    signature, err := SignData(privKey, []byte(data))
    if err != nil {
        panic(err)
    }

    // Verify signature
    if VerifySignature(publicKey, signature, []byte(data)) {
        println("Signature verification successful")
    } else {
        println("Signature verification failed")
    }

    // Encrypt and 'decrypt' data example
    encryptedData := EncryptData(data)
    println("Encrypted Data:", encryptedData)

    // Attempting to 'decrypt', which demonstrates retrieving the original format
    _, err = DecryptData(encryptedData)
    if err != nil {
        println("Error decrypting data:", err.Error())
    } else {
        println("Decrypted data obtained successfully")
    }
}
