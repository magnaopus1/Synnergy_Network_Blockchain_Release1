package quantum_resistance

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/cloudflare/circl/lattice/kyber"
)

// LatticeCrypto represents the structure for lattice-based cryptographic operations.
type LatticeCrypto struct {
	PrivateKey *kyber.PrivateKey
	PublicKey  *kyber.PublicKey
}

// NewLatticeCrypto initializes and returns a new instance of LatticeCrypto.
func NewLatticeCrypto() (*LatticeCrypto, error) {
	// Generate a new Kyber keypair
	privKey, pubKey, err := kyber.GenerateKeyPair(rand.Reader, kyber.ModeKyber768)
	if err != nil {
		return nil, err
	}

	return &LatticeCrypto{
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

// Encrypt encrypts the given plaintext using the public key.
func (lc *LatticeCrypto) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext cannot be empty")
	}

	// Encrypting the plaintext
	ciphertext, err := lc.PublicKey.Encrypt(plaintext, rand.Reader)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// Decrypt decrypts the given ciphertext using the private key.
func (lc *LatticeCrypto) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext cannot be empty")
	}

	// Decrypting the ciphertext
	plaintext, err := lc.PrivateKey.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// ExportPublicKey exports the public key in a format that can be easily transmitted.
func (lc *LatticeCrypto) ExportPublicKey() ([]byte, error) {
	return lc.PublicKey.MarshalBinary()
}

// ImportPublicKey imports a public key from a given binary format.
func ImportPublicKey(data []byte) (*kyber.PublicKey, error) {
	pubKey := &kyber.PublicKey{}
	err := pubKey.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}
