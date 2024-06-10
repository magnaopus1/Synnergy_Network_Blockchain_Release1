package authentication

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/pkg/errors"
)

// PKIManager manages the Public Key Infrastructure for the Synnergy Network.
type PKIManager struct {
	CA *x509.Certificate
	PrivateKey *rsa.PrivateKey
}

// NewPKIManager initializes a new PKI system with a root certificate and private key.
func NewPKIManager() (*PKIManager, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate private key")
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Synnergy Network"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:      true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create certificate")
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse certificate")
	}

	return &PKIManager{
		CA:         cert,
		PrivateKey: privateKey,
	}, nil
}

// GenerateCertificate generates a new certificate signed by the CA.
func (p *PKIManager) GenerateCertificate(subject pkix.Name) (*x509.Certificate, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0), // 1 year validity
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	childKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate key for certificate")
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, p.CA, &childKey.PublicKey, p.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create certificate")
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse certificate")
	}

	return cert, nil
}

// Example of creating a new PKIManager and generating a certificate.
func main() {
	pkiManager, err := NewPKIManager()
	if err != nil {
		panic(err)
	}

	userCert, err := pkiManager.GenerateCertificate(pkix.Name{
		CommonName: "User 123",
	})
	if err != nil {
		panic(err)
	}

	// Output the generated user certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: userCert.Raw})
	fmt.Println(string(certPEM))
}
