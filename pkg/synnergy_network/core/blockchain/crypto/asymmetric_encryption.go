package crypto

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "io/ioutil"
    "os"

    "golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/ecdsa"
    "golang.org/x/crypto/elliptic"
    "golang.org/x/crypto/sha3"
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

// RSAEncryptionExample provides an example of RSA encryption and decryption.
func RSAEncryptionExample() {
    privateKey, _ := GenerateRSAKeyPair(2048)
    SaveRSAPrivateKey("rsa_private.pem", privateKey)

    publicKey := &privateKey.PublicKey
    encryptedData, _ := EncryptWithRSA(publicKey, []byte("Hello, World!"))
    decryptedData, _ := DecryptWithRSA(privateKey, encryptedData)

    fmt.Println("Decrypted Data:", string(decryptedData))
    SecureDelete("rsa_private.pem")
}

// ECCEncryptionExample provides an example of ECC encryption and decryption.
func ECCEncryptionExample() {
    privateKey, _ := GenerateECCKeyPair()
    SaveECCPrivateKey("ecc_private.pem", privateKey)

    publicKey := &privateKey.PublicKey
    encryptedData, _ := EncryptWithECC(publicKey, []byte("Hello, World!"))
    decryptedData, _ := DecryptWithECC(privateKey, encryptedData)

    fmt.Println("Decrypted Data:", string(decryptedData))
    SecureDelete("ecc_private.pem")
}

// X25519EncryptionExample provides an example of X25519 encryption and decryption.
func X25519EncryptionExample() {
    privateKey, publicKey, _ := GenerateX25519KeyPair()

    encryptedData, _ := EncryptWithX25519(publicKey, []byte("Hello, World!"))
    decryptedData, _ := DecryptWithX25519(privateKey, encryptedData)

    fmt.Println("Decrypted Data:", string(decryptedData))
}
