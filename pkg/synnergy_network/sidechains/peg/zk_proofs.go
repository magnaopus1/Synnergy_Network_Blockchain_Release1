package peg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/gadget"
)

// ZKProof represents a zero-knowledge proof.
type ZKProof struct {
	PublicKey  string
	PrivateKey string
	Proof      []byte
}

// ZKProofManager manages zero-knowledge proofs.
type ZKProofManager struct {
	mu     sync.Mutex
	proofs map[string]*ZKProof
}

// NewZKProofManager creates a new instance of ZKProofManager.
func NewZKProofManager() *ZKProofManager {
	return &ZKProofManager{
		proofs: make(map[string]*ZKProof),
	}
}

// GenerateKeyPair generates a new public/private key pair for ZK proofs.
func (zkm *ZKProofManager) GenerateKeyPair() (string, string, error) {
	zkm.mu.Lock()
	defer zkm.mu.Unlock()

	privateKey, err := generatePrivateKey()
	if err != nil {
		return "", "", err
	}

	publicKey := generatePublicKey(privateKey)
	return publicKey, privateKey, nil
}

// CreateProof creates a zero-knowledge proof for the given data.
func (zkm *ZKProofManager) CreateProof(publicKey, privateKey, data string) (*ZKProof, error) {
	zkm.mu.Lock()
	defer zkm.mu.Unlock()

	proof, err := generateZKProof(publicKey, privateKey, data)
	if err != nil {
		return nil, err
	}

	zkProof := &ZKProof{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Proof:      proof,
	}
	zkm.proofs[publicKey] = zkProof
	return zkProof, nil
}

// VerifyProof verifies a zero-knowledge proof.
func (zkm *ZKProofManager) VerifyProof(publicKey, data string, proof []byte) (bool, error) {
	zkm.mu.Lock()
	defer zkm.mu.Unlock()

	zkProof, exists := zkm.proofs[publicKey]
	if !exists {
		return false, errors.New("proof not found")
	}

	isValid, err := verifyZKProof(publicKey, data, proof)
	if err != nil {
		return false, err
	}

	return isValid, nil
}

// generatePrivateKey generates a random private key.
func generatePrivateKey() (string, error) {
	privateKey := make([]byte, 32)
	_, err := rand.Read(privateKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(privateKey), nil
}

// generatePublicKey generates a public key from the given private key.
func generatePublicKey(privateKey string) string {
	hash := sha256.Sum256([]byte(privateKey))
	return hex.EncodeToString(hash[:])
}

// generateZKProof generates a zero-knowledge proof using the provided keys and data.
func generateZKProof(publicKey, privateKey, data string) ([]byte, error) {
	// Construct the circuit
	circuit := frontend.New()
	var (
		dataHash     = mimc.New()
		dataHashPre  = frontend.Variable{}
		dataVariable = frontend.Variable{}
	)

	// Input data hash
	dataHashPre.Assign(data)
	dataHash.Write(dataHashPre)
	dataHashVariable := dataHash.Sum()

	// Private key
	privateKeyVariable := frontend.Variable{}
	privateKeyVariable.Assign(privateKey)

	// Public key
	publicKeyVariable := frontend.Variable{}
	publicKeyVariable.Assign(publicKey)

	// Mimc hash
	gadget.MiMC().Hash(&circuit, privateKeyVariable, dataVariable)

	// Equality constraint
	circuit.AssertIsEqual(dataHashVariable, publicKeyVariable)

	// Compile the circuit
	r1cs, err := cs.Compile(ecc.BN254, circuit)
	if err != nil {
		return nil, err
	}

	// Proving key
	pk, vk, err := r1cs.Setup()
	if err != nil {
		return nil, err
	}

	// Prove
	proof, err := r1cs.Prove(pk)
	if err != nil {
		return nil, err
	}

	// Verify
	valid, err := r1cs.Verify(proof, vk)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.New("proof verification failed")
	}

	return proof, nil
}

// verifyZKProof verifies a zero-knowledge proof using the provided public key and data.
func verifyZKProof(publicKey, data string, proof []byte) (bool, error) {
	// Construct the circuit
	circuit := frontend.New()
	var (
		dataHash     = mimc.New()
		dataHashPre  = frontend.Variable{}
		dataVariable = frontend.Variable{}
	)

	// Input data hash
	dataHashPre.Assign(data)
	dataHash.Write(dataHashPre)
	dataHashVariable := dataHash.Sum()

	// Public key
	publicKeyVariable := frontend.Variable{}
	publicKeyVariable.Assign(publicKey)

	// Mimc hash
	gadget.MiMC().Hash(&circuit, publicKeyVariable, dataVariable)

	// Equality constraint
	circuit.AssertIsEqual(dataHashVariable, publicKeyVariable)

	// Compile the circuit
	r1cs, err := cs.Compile(ecc.BN254, circuit)
	if err != nil {
		return false, err
	}

	// Verifying key
	_, vk, err := r1cs.Setup()
	if err != nil {
		return false, err
	}

	// Verify
	valid, err := r1cs.Verify(proof, vk)
	if err != nil {
		return false, err
	}

	return valid, nil
}

// Example implementation of ZK proof generation and verification
func main() {
	zkm := NewZKProofManager()

	// Generate key pair
	publicKey, privateKey, err := zkm.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Failed to generate key pair: %v\n", err)
		return
	}

	// Create ZK proof
	data := "example data"
	zkProof, err := zkm.CreateProof(publicKey, privateKey, data)
	if err != nil {
		fmt.Printf("Failed to create ZK proof: %v\n", err)
		return
	}

	// Verify ZK proof
	isValid, err := zkm.VerifyProof(publicKey, data, zkProof.Proof)
	if err != nil {
		fmt.Printf("Failed to verify ZK proof: %v\n", err)
		return
	}

	fmt.Printf("ZK proof verification result: %v\n", isValid)
}
