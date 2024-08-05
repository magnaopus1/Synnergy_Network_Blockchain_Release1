package resource_markets

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "fmt"
    "log"
)

// ResourceQualityAssurance represents the structure for ensuring quality in resource allocation.
type ResourceQualityAssurance struct {
    MinCPUSpecs       int // Minimum CPU specifications
    MinMemorySpecs    int // Minimum Memory specifications
    MinNetworkBandwidth int // Minimum Network Bandwidth specifications
    MinStorageSpecs   int // Minimum Storage specifications
    ValidatorPublicKey  *rsa.PublicKey // Public key for validating resource integrity
    ValidatorPrivateKey *rsa.PrivateKey // Private key for signing validations
}

// NewResourceQualityAssurance initializes a new quality assurance instance with security keys.
func NewResourceQualityAssurance(minCPUSpecs, minMemorySpecs, minNetworkBandwidth, minStorageSpecs int) (*ResourceQualityAssurance, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, fmt.Errorf("failed to generate private key: %v", err)
    }

    return &ResourceQualityAssurance{
        MinCPUSpecs:        minCPUSpecs,
        MinMemorySpecs:     minMemorySpecs,
        MinNetworkBandwidth: minNetworkBandwidth,
        MinStorageSpecs:    minStorageSpecs,
        ValidatorPublicKey:  &privateKey.PublicKey,
        ValidatorPrivateKey: privateKey,
    }, nil
}

// ValidateResource ensures that the provided resources meet the minimum specifications.
func (rqa *ResourceQualityAssurance) ValidateResource(cpu, memory, networkBandwidth, storage int) bool {
    return cpu >= rqa.MinCPUSpecs && memory >= rqa.MinMemorySpecs && networkBandwidth >= rqa.MinNetworkBandwidth && storage >= rqa.MinStorageSpecs
}

// SignValidation signs a validation message indicating resource quality assurance has passed.
func (rqa *ResourceQualityAssurance) SignValidation(message []byte) ([]byte, error) {
    hashed := sha256.Sum256(message)
    signature, err := rsa.SignPKCS1v15(rand.Reader, rqa.ValidatorPrivateKey, crypto.SHA256, hashed[:])
    if err != nil {
        return nil, fmt.Errorf("failed to sign validation: %v", err)
    }
    return signature, nil
}

// VerifyValidation verifies the signed message to confirm resource quality assurance.
func (rqa *ResourceQualityAssurance) VerifyValidation(message, signature []byte) error {
    hashed := sha256.Sum256(message)
    err := rsa.VerifyPKCS1v15(rqa.ValidatorPublicKey, crypto.SHA256, hashed[:], signature)
    if err != nil {
        return errors.New("verification failed: invalid signature")
    }
    return nil
}

// ExportPublicKeyPEM exports the public key in PEM format for distribution.
func (rqa *ResourceQualityAssurance) ExportPublicKeyPEM() ([]byte, error) {
    pubKeyBytes := x509.MarshalPKCS1PublicKey(rqa.ValidatorPublicKey)
    pubKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: pubKeyBytes,
    })
    return pubKeyPEM, nil
}

// ImportPublicKeyPEM imports a public key from PEM format.
func (rqa *ResourceQualityAssurance) ImportPublicKeyPEM(pubKeyPEM []byte) error {
    block, _ := pem.Decode(pubKeyPEM)
    if block == nil || block.Type != "RSA PUBLIC KEY" {
        return errors.New("failed to decode PEM block containing public key")
    }

    pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse public key: %v", err)
    }

    rqa.ValidatorPublicKey = pub
    return nil
}

// ImportPrivateKeyPEM imports a private key from PEM format.
func (rqa *ResourceQualityAssurance) ImportPrivateKeyPEM(privateKeyPEM []byte) error {
    block, _ := pem.Decode(privateKeyPEM)
    if block == nil || block.Type != "RSA PRIVATE KEY" {
        return errors.New("failed to decode PEM block containing private key")
    }

    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse private key: %v", err)
    }

    rqa.ValidatorPrivateKey = priv
    return nil
}

// LogQualityCheck logs the results of a resource quality check.
func (rqa *ResourceQualityAssurance) LogQualityCheck(resourceID string, passed bool) {
    if passed {
        log.Printf("Resource %s passed quality check.\n", resourceID)
    } else {
        log.Printf("Resource %s failed quality check.\n", resourceID)
    }
}
