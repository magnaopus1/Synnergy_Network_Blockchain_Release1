package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/cloudflare/circl/dilithium"
	"github.com/cloudflare/circl/hybridhash"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber"
	"github.com/cloudflare/circl/sign"
)

// QuantumKeyPair represents a quantum-resistant key pair.
type QuantumKeyPair struct {
	PrivateKey kem.PrivateKey
	PublicKey  kem.PublicKey
	SignKey    sign.PrivateKey
}

// GenerateQuantumKeyPair generates a new quantum-resistant key pair using Kyber and Dilithium.
func GenerateQuantumKeyPair() (*QuantumKeyPair, error) {
	// Kyber for encryption
	scheme := kyber.NewKyber768()
	pubKeyEnc, privKeyEnc, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Dilithium for signature
	mode := dilithium.Mode2
	pubKeySign, privKeySign, err := mode.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	return &QuantumKeyPair{
		PrivateKey: privKeyEnc,
		PublicKey:  pubKeyEnc,
		SignKey:    privKeySign,
	}, nil
}

// SavePrivateKey saves the private key to a file.
func (kp *QuantumKeyPair) SavePrivateKey(filename string) error {
	privKeyBytes := kp.PrivateKey.Bytes()
	privSignKeyBytes := kp.SignKey.Bytes()

	data := append(privKeyBytes, privSignKeyBytes...)
	return saveToFile(data, filename)
}

// LoadPrivateKey loads a private key from a file.
func LoadPrivateKey(filename string) (*QuantumKeyPair, error) {
	data, err := loadFromFile(filename)
	if err != nil {
		return nil, err
	}

	scheme := kyber.NewKyber768()
	privKeyEnc, err := scheme.UnmarshalBinaryPrivateKey(data[:scheme.PrivateKeySize()])
	if err != nil {
		return nil, err
	}

	mode := dilithium.Mode2
	privKeySign, err := mode.UnmarshalBinaryPrivateKey(data[scheme.PrivateKeySize():])
	if err != nil {
		return nil, err
	}

	return &QuantumKeyPair{
		PrivateKey: privKeyEnc,
		PublicKey:  privKeyEnc.Public(),
		SignKey:    privKeySign,
	}, nil
}

// SavePublicKey saves the public key to a file.
func (kp *QuantumKeyPair) SavePublicKey(filename string) error {
	pubKeyBytes := kp.PublicKey.Bytes()
	pubSignKeyBytes := kp.SignKey.Public().Bytes()

	data := append(pubKeyBytes, pubSignKeyBytes...)
	return saveToFile(data, filename)
}

// LoadPublicKey loads a public key from a file.
func LoadPublicKey(filename string) (*QuantumKeyPair, error) {
	data, err := loadFromFile(filename)
	if err != nil {
		return nil, err
	}

	scheme := kyber.NewKyber768()
	pubKeyEnc, err := scheme.UnmarshalBinaryPublicKey(data[:scheme.PublicKeySize()])
	if err != nil {
		return nil, err
	}

	mode := dilithium.Mode2
	pubKeySign, err := mode.UnmarshalBinaryPublicKey(data[scheme.PublicKeySize():])
	if err != nil {
		return nil, err
	}

	return &QuantumKeyPair{
		PublicKey: pubKeyEnc,
		SignKey:   pubKeySign,
	}, nil
}

// EncryptData encrypts data using the public key.
func (kp *QuantumKeyPair) EncryptData(data []byte) ([]byte, error) {
	scheme := kyber.NewKyber768()
	encData, err := scheme.Encrypt(kp.PublicKey, data)
	if err != nil {
		return nil, err
	}

	return encData, nil
}

// DecryptData decrypts data using the private key.
func (kp *QuantumKeyPair) DecryptData(data []byte) ([]byte, error) {
	scheme := kyber.NewKyber768()
	decData, err := scheme.Decrypt(kp.PrivateKey, data)
	if err != nil {
		return nil, err
	}

	return decData, nil
}

// SignData signs data using the private key.
func (kp *QuantumKeyPair) SignData(data []byte) ([]byte, error) {
	signature, err := kp.SignKey.Sign(data)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// VerifySignature verifies the signature using the public key.
func (kp *QuantumKeyPair) VerifySignature(data, signature []byte) bool {
	return kp.SignKey.Public().Verify(data, signature) == nil
}

// HashAddress hashes a public key to create a blockchain address.
func (kp *QuantumKeyPair) HashAddress() string {
	pubBytes := kp.PublicKey.Bytes()
	hash := sha3.New256()
	hash.Write(pubBytes)
	return hex.EncodeToString(hash.Sum(nil))
}

// saveToFile saves data to a file.
func saveToFile(data []byte, filename string) error {
	return ioutil.WriteFile(filename, data, 0600)
}

// loadFromFile loads data from a file.
func loadFromFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// EncryptHybridData encrypts data using a hybrid approach (ECDSA + Quantum).
func EncryptHybridData(data []byte, kp *QuantumKeyPair) ([]byte, error) {
	// Encrypt data using quantum-resistant public key
	encData, err := kp.EncryptData(data)
	if err != nil {
		return nil, err
	}

	// Generate a SHA-256 hash of the data
	hash := sha256.Sum256(data)

	// Sign the hash with the private key
	signature, err := kp.SignData(hash[:])
	if err != nil {
		return nil, err
	}

	// Combine encrypted data and signature
	return append(encData, signature...), nil
}

// DecryptHybridData decrypts data using a hybrid approach (ECDSA + Quantum).
func DecryptHybridData(data []byte, kp *QuantumKeyPair) ([]byte, error) {
	scheme := kyber.NewKyber768()
	// Determine the lengths of the encrypted data and signature
	encDataLen := scheme.CiphertextSize()
	signatureLen := kp.SignKey.Public().SignatureSize()

	if len(data) < encDataLen+signatureLen {
		return nil, errors.New("invalid data length")
	}

	// Separate encrypted data and signature
	encData := data[:encDataLen]
	signature := data[encDataLen:]

	// Decrypt the data using the quantum-resistant private key
	decData, err := kp.DecryptData(encData)
	if err != nil {
		return nil, err
	}

	// Verify the signature
	hash := sha256.Sum256(decData)
	if !kp.VerifySignature(hash[:], signature) {
		return nil, errors.New("invalid signature")
	}

	return decData, nil
}

// SecureKeyExchange performs a quantum-resistant key exchange.
func SecureKeyExchange() (kem.Encapsulation, kem.KeyPair, error) {
	scheme := kyber.NewKyber768()
	// Generate ephemeral key pair
	ephemeralPubKey, ephemeralPrivKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Perform key encapsulation
	encapsulation, err := scheme.Encapsulate(ephemeralPubKey)
	if err != nil {
		return nil, nil, err
	}

	return encapsulation, ephemeralPrivKey, nil
}

// SecureHash combines multiple hashing algorithms to create a quantum-resistant hash.
func SecureHash(data []byte) string {
	// Hash using SHA-256
	sha256Hash := sha256.Sum256(data)

	// Hash using SHA-3
	sha3Hash := sha3.New256()
	sha3Hash.Write(sha256Hash[:])

	return hex.EncodeToString(sha3Hash.Sum(nil))
}
