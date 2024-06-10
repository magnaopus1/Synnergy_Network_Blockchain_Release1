package crosschainoracles

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"sync"
)

// Oracle represents a node in the decentralized oracle network that fetches and verifies data.
type Oracle struct {
	PublicKey *rsa.PublicKey
	Client    *http.Client
}

// OracleNetwork manages a network of decentralized oracles.
type OracleNetwork struct {
	Oracles []*Oracle
	mutex   sync.Mutex
}

// NewOracle creates a new oracle with the given public key path.
func NewOracle(publicKeyPath string) (*Oracle, error) {
	keyData, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing the public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not of type RSA")
	}

	return &Oracle{
		PublicKey: rsaPubKey,
		Client:    &http.Client{},
	}, nil
}

// AddOracle adds a new oracle to the network.
func (net *OracleNetwork) AddOracle(oracle *Oracle) {
	net.mutex.Lock()
	defer net.mutex.Unlock()
	net.Oracles = append(net.Oracles, oracle)
}

// VerifyData concurrently verifies data across multiple oracles.
func (net *OracleNetwork) VerifyData(data []byte, signature []byte) bool {
	var wg sync.WaitGroup
	resultChannel := make(chan bool, len(net.Oracles))

	for _, oracle := range net.Oracles {
		wg.Add(1)
		go func(orc *Oracle) {
			defer wg.Done()
			if err := orc.VerifySignature(data, signature); err == nil {
				resultChannel <- true
			}
		}(oracle)
	}

	wg.Wait()
	close(resultChannel)

	for result := range resultChannel {
		if result {
			return true
		}
	}

	return false
}

// VerifySignature verifies the digital signature of the data using the oracle's public key.
func (o *Oracle) VerifySignature(data []byte, signature []byte) error {
	hashed := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(o.PublicKey, crypto.SHA256, hashed[:], signature)
}

// Example usage
func main() {
	network := &OracleNetwork{}
	oracle, err := NewOracle("path/to/public_key.pem")
	if err != nil {
		panic(err)
	}
	network.AddOracle(oracle)

	// Example data and signature to verify
	data := []byte("data to verify")
	signature := []byte{} // Actual byte slice of the signature

	if network.VerifyData(data, signature) {
		println("Data verification successful across the network")
	} else {
		println("Data verification failed")
	}
}
