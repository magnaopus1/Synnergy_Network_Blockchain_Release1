package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeyManager manages cryptographic keys for the Synnergy Network.
type KeyManager struct{}

// GenerateECDSAKey generates a new ECDSA private key using the specified elliptic curve.
func (km *KeyManager) GenerateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	if curve == nil {
		return nil, errors.New("no elliptic curve provided")
	}
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %v", err)
	}
	return privateKey, nil
}

// SerializePublicKey serializes an ECDSA public key to a string format.
func SerializePublicKey(pubKey *ecdsa.PublicKey) (string, error) {
	if pubKey == nil {
		return "", errors.New("public key is nil")
	}
	publicKeyBytes := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	return fmt.Sprintf("%x", publicKeyBytes), nil
}

// SerializePrivateKey serializes an ECDSA private key to a string format.
func SerializePrivateKey(privKey *ecdsa.PrivateKey) (string, error) {
	if privKey == nil {
		return "", errors.New("private key is nil")
	}
	return fmt.Sprintf("%x", privKey.D.Bytes()), nil
}

// Example usage
func main() {
	km := &KeyManager{}
	// Generate a key using the P256 curve
	privateKey, err := km.GenerateECDSAKey(elliptic.P256())
	if err != nil {
		fmt.Println("Error generating ECDSA key:", err)
		return
	}

	// Serialize the public key
	pubKeyString, err := SerializePublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Println("Error serializing public key:", err)
		return
	}

	// Serialize the private key
	privKeyString, err := SerializePrivateKey(privateKey)
	if err != nil {
		fmt.Println("Error serializing private key:", err)
		return
	}

	fmt.Println("Public Key:", pubKeyString)
	fmt.Println("Private Key:", privKeyString)
}

