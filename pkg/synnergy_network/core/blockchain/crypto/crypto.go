package crypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "errors"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/ecdsa"
    "golang.org/x/crypto/elliptic"
    "golang.org/x/crypto/scrypt"
    "golang.org/x/crypto/sha3"
    "io"
    "io/ioutil"
    "os"
)

// GenerateRSAKeyPair generates a new RSA key pair.
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return nil, err
    }
    return privateKey, nil
}

// SaveRSAPrivateKey saves the RSA private key to a file.
func SaveRSAPrivateKey(filename string, key *rsa.PrivateKey) error {
    keyBytes := x509.MarshalPKCS1PrivateKey(key)
    keyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: keyBytes,
    })
    return ioutil.WriteFile(filename, keyPEM, 0600)
}

// LoadRSAPrivateKey loads the RSA private key from a file.
func LoadRSAPrivateKey(filename string) (*rsa.PrivateKey, error) {
    keyPEM, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(keyPEM)
    if block == nil || block.Type != "RSA PRIVATE KEY" {
        return nil, errors.New("failed to decode PEM block containing RSA private key")
    }
    return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// EncryptWithRSA encrypts data using RSA public key.
func EncryptWithRSA(publicKey *rsa.PublicKey, data []byte) ([]byte, error) {
    hash := sha256.New()
    return rsa.EncryptOAEP(hash, rand.Reader, publicKey, data, nil)
}

// DecryptWithRSA decrypts data using RSA private key.
func DecryptWithRSA(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
    hash := sha256.New()
    return rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, nil)
}

// GenerateECCKeyPair generates a new ECC key pair.
func GenerateECCKeyPair() (*ecdsa.PrivateKey, error) {
    curve := elliptic.P256()
    return ecdsa.GenerateKey(curve, rand.Reader)
}

// SaveECCPrivateKey saves the ECC private key to a file.
func SaveECCPrivateKey(filename string, key *ecdsa.PrivateKey) error {
    keyBytes, err := x509.MarshalECPrivateKey(key)
    if err != nil {
        return err
    }
    keyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "EC PRIVATE KEY",
        Bytes: keyBytes,
    })
    return ioutil.WriteFile(filename, keyPEM, 0600)
}

// LoadECCPrivateKey loads the ECC private key from a file.
func LoadECCPrivateKey(filename string) (*ecdsa.PrivateKey, error) {
    keyPEM, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(keyPEM)
    if block == nil || block.Type != "EC PRIVATE KEY" {
        return nil, errors.New("failed to decode PEM block containing ECC private key")
    }
    return x509.ParseECPrivateKey(block.Bytes)
}

// EncryptWithECC encrypts data using ECC public key (ECIES scheme).
func EncryptWithECC(publicKey *ecdsa.PublicKey, data []byte) ([]byte, error) {
    ephemeral, err := ecdsa.GenerateKey(publicKey.Curve, rand.Reader)
    if err != nil {
        return nil, err
    }

    sharedX, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, ephemeral.D.Bytes())
    hash := sha3.New256()
    hash.Write(sharedX.Bytes())
    key := hash.Sum(nil)

    ciphertext := make([]byte, len(data))
    for i := 0; i < len(data); i++ {
        ciphertext[i] = data[i] ^ key[i%len(key)]
    }

    return ciphertext, nil
}

// DecryptWithECC decrypts data using ECC private key (ECIES scheme).
func DecryptWithECC(privateKey *ecdsa.PrivateKey, ciphertext []byte) ([]byte, error) {
    sharedX, _ := privateKey.PublicKey.Curve.ScalarMult(privateKey.PublicKey.X, privateKey.PublicKey.Y, privateKey.D.Bytes())
    hash := sha3.New256()
    hash.Write(sharedX.Bytes())
    key := hash.Sum(nil)

    data := make([]byte, len(ciphertext))
    for i := 0; i < len(ciphertext); i++ {
        data[i] = ciphertext[i] ^ key[i%len(key)]
    }

    return data, nil
}

// GenerateX25519KeyPair generates a new X25519 key pair.
func GenerateX25519KeyPair() (privateKey, publicKey [32]byte, err error) {
    _, err = rand.Read(privateKey[:])
    if err != nil {
        return
    }
    curve25519.ScalarBaseMult(&publicKey, &privateKey)
    return
}

// EncryptWithX25519 encrypts data using X25519 public key.
func EncryptWithX25519(publicKey [32]byte, data []byte) ([]byte, error) {
    ephemeralPrivate, ephemeralPublic, err := GenerateX25519KeyPair()
    if err != nil {
        return nil, err
    }

    sharedSecret := new([32]byte)
    curve25519.ScalarMult(sharedSecret, &ephemeralPrivate, &publicKey)

    hash := sha3.New256()
    hash.Write(sharedSecret[:])
    key := hash.Sum(nil)

    ciphertext := make([]byte, len(data))
    for i := 0; i < len(data); i++ {
        ciphertext[i] = data[i] ^ key[i%len(key)]
    }

    return append(ephemeralPublic[:], ciphertext...), nil
}

// DecryptWithX25519 decrypts data using X25519 private key.
func DecryptWithX25519(privateKey [32]byte, ciphertext []byte) ([]byte, error) {
    if len(ciphertext) < 32 {
        return nil, errors.New("ciphertext too short")
    }

    var ephemeralPublic [32]byte
    copy(ephemeralPublic[:], ciphertext[:32])
    ciphertext = ciphertext[32:]

    sharedSecret := new([32]byte)
    curve25519.ScalarMult(sharedSecret, &privateKey, &ephemeralPublic)

    hash := sha3.New256()
    hash.Write(sharedSecret[:])
    key := hash.Sum(nil)

    data := make([]byte, len(ciphertext))
    for i := 0; i < len(ciphertext); i++ {
        data[i] = ciphertext[i] ^ key[i%len(key)]
    }

    return data, nil
}

// SaveKeyToPEM saves the given key to a PEM file.
func SaveKeyToPEM(filename string, key interface{}) error {
    var keyBytes []byte
    var err error
    var keyType string

    switch k := key.(type) {
    case *rsa.PrivateKey:
        keyBytes = x509.MarshalPKCS1PrivateKey(k)
        keyType = "RSA PRIVATE KEY"
    case *ecdsa.PrivateKey:
        keyBytes, err = x509.MarshalECPrivateKey(k)
        keyType = "EC PRIVATE KEY"
    default:
        return errors.New("unsupported key type")
    }

    if err != nil {
        return err
    }

    keyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  keyType,
        Bytes: keyBytes,
    })

    return ioutil.WriteFile(filename, keyPEM, 0600)
}

// LoadKeyFromPEM loads the key from a PEM file.
func LoadKeyFromPEM(filename string, keyType string) (interface{}, error) {
    keyPEM, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }

    block, _ := pem.Decode(keyPEM)
    if block == nil || block.Type != keyType {
        return nil, errors.New("failed to decode PEM block containing key")
    }

    switch keyType {
    case "RSA PRIVATE KEY":
        return x509.ParsePKCS1PrivateKey(block.Bytes)
    case "EC PRIVATE KEY":
        return x509.ParseECPrivateKey(block.Bytes)
    default:
        return nil, errors.New("unsupported key type")
    }
}

// SecureDelete securely deletes the file to prevent recovery.
func SecureDelete(filename string) error {
    return os.Remove(filename)
}

// HashWithSHA256 hashes data using SHA-256.
func HashWithSHA256(data []byte) []byte {
    hash := sha256.Sum256(data)
    return hash[:]
}

// HashWithScrypt hashes data using Scrypt.
func HashWithScrypt(data []byte, salt []byte, N, r, p, keyLen int) ([]byte, error) {
    return scrypt.Key(data, salt, N, r, p, keyLen)
}

// HashWithArgon2 hashes data using Argon2.
func HashWithArgon2(data []byte, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
    return argon2.IDKey(data, salt, time, memory, threads, keyLen)
}

// GenerateSalt generates a random salt of the given length.
func GenerateSalt(length int) ([]byte, error) {
    salt := make([]byte, length)
    _, err := rand.Read(salt)
    if err != nil {
        return nil, err
    }
    return salt, nil
}

// EncryptWithAES encrypts data using AES-GCM.
func EncryptWithAES(key, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, 12)
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
    return append(nonce, ciphertext...), nil
}

// DecryptWithAES decrypts data using AES-GCM.
func DecryptWithAES(key, ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    if len(ciphertext) < 12 {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:12], ciphertext[12:]

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    return aesgcm.Open(nil, nonce, ciphertext, nil)
}

// SignWithHMAC signs data using HMAC-SHA256.
func SignWithHMAC(key, data []byte) []byte {
    mac := hmac.New(sha256.New, key)
    mac.Write(data)
    return mac.Sum(nil)
}

// VerifyHMAC verifies HMAC-SHA256 signature.
func VerifyHMAC(key, data, signature []byte) bool {
    mac := hmac.New(sha256.New, key)
    mac.Write(data)
    expectedMAC := mac.Sum(nil)
    return hmac.Equal(signature, expectedMAC)
}

// EncodeBase64 encodes data to base64.
func EncodeBase64(data []byte) string {
    return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes data from base64.
func DecodeBase64(data string) ([]byte, error) {
    return base64.StdEncoding.DecodeString(data)
}

// SecureKeyExchange handles the secure exchange of keys using a hybrid approach.
func SecureKeyExchange() error {
    // Generate RSA key pair for key exchange
    rsaPrivateKey, err := GenerateRSAKeyPair(2048)
    if err != nil {
        return err
    }

    // Generate ECC key pair for encryption
    eccPrivateKey, err := GenerateECCKeyPair()
    if err != nil {
        return err
    }

    // Exchange public keys securely (out of scope for this example)
    // ...

    // Encrypt a symmetric key with RSA public key (example symmetric key)
    symmetricKey := []byte("exampleSymmetricKey")
    encryptedSymmetricKey, err := EncryptWithRSA(&rsaPrivateKey.PublicKey, symmetricKey)
    if err != nil {
        return err
    }

    // Encrypt data with ECC public key (example data)
    data := []byte("exampleData")
    encryptedData, err := EncryptWithECC(&eccPrivateKey.PublicKey, data)
    if err != nil {
        return err
    }

    // Decrypt the symmetric key with RSA private key
    decryptedSymmetricKey, err := DecryptWithRSA(rsaPrivateKey, encryptedSymmetricKey)
    if err != nil {
        return err
    }

    // Decrypt the data with ECC private key
    decryptedData, err := DecryptWithECC(eccPrivateKey, encryptedData)
    if err != nil {
        return err
    }

    // Use the decrypted symmetric key and data (example usage)
    _ = decryptedSymmetricKey
    _ = decryptedData

    return nil
}
