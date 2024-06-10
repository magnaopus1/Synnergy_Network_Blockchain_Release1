package ricardian_contracts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// GenerateKeyPair generates a new ECDSA private and public key pair using the P-256 elliptic curve.
func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating key pair: %v", err)
	}
	return privKey, &privKey.PublicKey, nil
}

// SignData signs the provided data using the given private key and returns the signature.
func SignData(data []byte, privKey *ecdsa.PrivateKey) (string, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("error signing data: %v", err)
	}
	signature := append(r.Bytes(), s.Bytes()...)
	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifySignature verifies the signature of the provided data using the given public key.
func VerifySignature(data []byte, signature string, pubKey *ecdsa.PublicKey) (bool, error) {
	hash := sha256.Sum256(data)
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("error decoding signature: %v", err)
	}
	r := big.Int{}
	s := big.Int{}
	sigLen := len(signatureBytes)
	r.SetBytes(signatureBytes[:(sigLen / 2)])
	s.SetBytes(signatureBytes[(sigLen / 2):])
	return ecdsa.Verify(pubKey, hash[:], &r, &s), nil
}

// MarshalPublicKeyToPEM marshals an ECDSA public key to a PEM-encoded string.
func MarshalPublicKeyToPEM(pubKey *ecdsa.PublicKey) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("error marshalling public key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	return string(pubKeyPEM), nil
}

// UnmarshalPublicKeyFromPEM unmarshals a PEM-encoded ECDSA public key string.
func UnmarshalPublicKeyFromPEM(pubKeyPEM string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}
	return ecdsaPubKey, nil
}

// MarshalPrivateKeyToPEM marshals an ECDSA private key to a PEM-encoded string.
func MarshalPrivateKeyToPEM(privKey *ecdsa.PrivateKey) (string, error) {
	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", fmt.Errorf("error marshalling private key: %v", err)
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	return string(privKeyPEM), nil
}

// UnmarshalPrivateKeyFromPEM unmarshals a PEM-encoded ECDSA private key string.
func UnmarshalPrivateKeyFromPEM(privKeyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %v", err)
	}
	return privKey, nil
}

// Example usage
func main() {
	// Generate a new ECDSA key pair
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error generating key pair: %v\n", err)
		return
	}

	// Sign a message
	message := "This is a sample message for signing."
	signature, err := SignData([]byte(message), privKey)
	if err != nil {
		fmt.Printf("Error signing data: %v\n", err)
		return
	}
	fmt.Printf("Signature: %s\n", signature)

	// Verify the signature
	isValid, err := VerifySignature([]byte(message), signature, pubKey)
	if err != nil {
		fmt.Printf("Error verifying signature: %v\n", err)
		return
	}
	if isValid {
		fmt.Println("Signature verification succeeded.")
	} else {
		fmt.Println("Signature verification failed.")
	}

	// Marshal and unmarshal public key to/from PEM
	pubKeyPEM, err := MarshalPublicKeyToPEM(pubKey)
	if err != nil {
		fmt.Printf("Error marshalling public key: %v\n", err)
		return
	}
	fmt.Printf("Public Key PEM:\n%s\n", pubKeyPEM)

	unmarshalledPubKey, err := UnmarshalPublicKeyFromPEM(pubKeyPEM)
	if err != nil {
		fmt.Printf("Error unmarshalling public key: %v\n", err)
		return
	}

	// Verify the signature with the unmarshalled public key
	isValid, err = VerifySignature([]byte(message), signature, unmarshalledPubKey)
	if err != nil {
		fmt.Printf("Error verifying signature with unmarshalled public key: %v\n", err)
		return
	}
	if isValid {
		fmt.Println("Signature verification with unmarshalled public key succeeded.")
	} else {
		fmt.Println("Signature verification with unmarshalled public key failed.")
	}
}
