package identity_verification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Node represents a node in the blockchain network.
type Node struct {
	ID        string
	PublicKey *ecdsa.PublicKey
	Cert      *x509.Certificate
}

// TrustManager manages the trust establishment for nodes.
type TrustManager struct {
	nodes map[string]*Node
}

// NewTrustManager creates a new TrustManager instance.
func NewTrustManager() *TrustManager {
	return &TrustManager{
		nodes: make(map[string]*Node),
	}
}

// GenerateKeyPair generates a new ECDSA key pair.
func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

// GenerateCertificate generates a new self-signed certificate for the given public key.
func GenerateCertificate(publicKey *ecdsa.PublicKey) (*x509.Certificate, error) {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, publicKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// RegisterNode registers a new node with its public key and certificate.
func (tm *TrustManager) RegisterNode(id string, publicKey *ecdsa.PublicKey, cert *x509.Certificate) error {
	tm.nodes[id] = &Node{
		ID:        id,
		PublicKey: publicKey,
		Cert:      cert,
	}
	return nil
}

// EstablishTrust establishes trust between two nodes using their certificates.
func (tm *TrustManager) EstablishTrust(nodeID1, nodeID2 string) error {
	node1, exists1 := tm.nodes[nodeID1]
	node2, exists2 := tm.nodes[nodeID2]
	if !exists1 || !exists2 {
		return errors.New("one or both nodes not found")
	}

	opts := x509.VerifyOptions{}
	if _, err := node1.Cert.Verify(opts); err != nil {
		return errors.New("node1 certificate verification failed")
	}
	if _, err := node2.Cert.Verify(opts); err != nil {
		return errors.New("node2 certificate verification failed")
	}

	return nil
}

// VerifyIdentity verifies the identity of a node using its certificate and a signed message.
func (tm *TrustManager) VerifyIdentity(id string, message, signature []byte) error {
	node, exists := tm.nodes[id]
	if !exists {
		return errors.New("node not found")
	}

	hash := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(node.PublicKey, hash[:], signature) {
		return errors.New("signature verification failed")
	}

	if _, err := node.Cert.Verify(x509.VerifyOptions{}); err != nil {
		return errors.New("certificate verification failed")
	}

	return nil
}

// EncodePublicKey encodes an ECDSA public key to PEM format.
func EncodePublicKey(publicKey *ecdsa.PublicKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block), nil
}

// DecodePublicKey decodes an ECDSA public key from PEM format.
func DecodePublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("not ECDSA public key")
	}
}

// EncodeCertificate encodes an x509 certificate to PEM format.
func EncodeCertificate(cert *x509.Certificate) ([]byte, error) {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(block), nil
}

// DecodeCertificate decodes an x509 certificate from PEM format.
func DecodeCertificate(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// SignMessage signs a message using the given private key.
func SignMessage(privateKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}
	return append(r.Bytes(), s.Bytes()...), nil
}

// VerifyMessage verifies a signed message using the given public key.
func VerifyMessage(publicKey *ecdsa.PublicKey, message, signature []byte) bool {
	hash := sha256.Sum256(message)
	return ecdsa.VerifyASN1(publicKey, hash[:], signature)
}

func main() {
	tm := NewTrustManager()

	// Example of generating a key pair and self-signed certificate
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		return
	}

	cert, err := GenerateCertificate(publicKey)
	if err != nil {
		fmt.Println("Error generating certificate:", err)
		return
	}

	// Register the node with the TrustManager
	nodeID := "node1"
	err = tm.RegisterNode(nodeID, publicKey, cert)
	if err != nil {
		fmt.Println("Error registering node:", err)
		return
	}

	// Example message signing and verification
	message := []byte("This is a test message")
	signature, err := SignMessage(privateKey, message)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}

	err = tm.VerifyIdentity(nodeID, message, signature)
	if err != nil {
		fmt.Println("Identity verification failed:", err)
	} else {
		fmt.Println("Identity verification succeeded")
	}

	// Establish trust between two nodes (node1 and node2)
	// Generating key pair and certificate for node2
	privateKey2, publicKey2, err := GenerateKeyPair()
	if err != nil {
		fmt.Println("Error generating key pair for node2:", err)
		return
	}

	cert2, err := GenerateCertificate(publicKey2)
	if err != nil {
		fmt.Println("Error generating certificate for node2:", err)
		return
	}

	nodeID2 := "node2"
	err = tm.RegisterNode(nodeID2, publicKey2, cert2)
	if err != nil {
		fmt.Println("Error registering node2:", err)
		return
	}

	err = tm.EstablishTrust(nodeID, nodeID2)
	if err != nil {
		fmt.Println("Trust establishment failed:", err)
	} else {
		fmt.Println("Trust established successfully between node1 and node2")
	}
}
