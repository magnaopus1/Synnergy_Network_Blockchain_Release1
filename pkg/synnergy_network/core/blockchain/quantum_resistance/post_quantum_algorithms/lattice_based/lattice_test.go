package lattice_based

import (
	"crypto/rand"
	"math/big"
	"testing"
)

const (
	testMessageLWE = "This is a test message for LWE encryption."
	testMessageRingLWE = "This is a test message for Ring-LWE encryption."
)

// Test vector operations
func TestVectorOperations(t *testing.T) {
	modulus := big.NewInt(qLWE)
	v1, err := generateRandomVector(nLWE, modulus)
	if err != nil {
		t.Fatalf("Failed to generate random vector: %v", err)
	}
	v2, err := generateRandomVector(nLWE, modulus)
	if err != nil {
		t.Fatalf("Failed to generate random vector: %v", err)
	}

	// Test addition
	addResult := v1.add(v2, modulus)
	for i := 0; i < nLWE; i++ {
		expected := new(big.Int).Add(v1.coeffs[i], v2.coeffs[i]).Mod(new(big.Int).Add(v1.coeffs[i], v2.coeffs[i]), modulus)
		if addResult.coeffs[i].Cmp(expected) != 0 {
			t.Errorf("Addition failed at index %d: got %v, want %v", i, addResult.coeffs[i], expected)
		}
	}

	// Test subtraction
	subResult := v1.sub(v2, modulus)
	for i := 0; i < nLWE; i++ {
		expected := new(big.Int).Sub(v1.coeffs[i], v2.coeffs[i]).Mod(new(big.Int).Sub(v1.coeffs[i], v2.coeffs[i]), modulus)
		if subResult.coeffs[i].Cmp(expected) != 0 {
			t.Errorf("Subtraction failed at index %d: got %v, want %v", i, subResult.coeffs[i], expected)
		}
	}

	// Test scalar multiplication
	scalar := big.NewInt(5)
	scalarMulResult := v1.scalarMul(scalar, modulus)
	for i := 0; i < nLWE; i++ {
		expected := new(big.Int).Mul(v1.coeffs[i], scalar).Mod(new(big.Int).Mul(v1.coeffs[i], scalar), modulus)
		if scalarMulResult.coeffs[i].Cmp(expected) != 0 {
			t.Errorf("Scalar multiplication failed at index %d: got %v, want %v", i, scalarMulResult.coeffs[i], expected)
		}
	}

	// Test inner product
	innerProductResult := v1.innerProduct(v2, modulus)
	expectedInnerProduct := big.NewInt(0)
	for i := 0; i < nLWE; i++ {
		term := new(big.Int).Mul(v1.coeffs[i], v2.coeffs[i])
		expectedInnerProduct.Add(expectedInnerProduct, term)
	}
	expectedInnerProduct.Mod(expectedInnerProduct, modulus)
	if innerProductResult.Cmp(expectedInnerProduct) != 0 {
		t.Errorf("Inner product failed: got %v, want %v", innerProductResult, expectedInnerProduct)
	}
}

// Test LWE key generation, encryption, and decryption
func TestLWEScheme(t *testing.T) {
	// Generate key pair
	keyPair, err := KeyGenLWE()
	if err != nil {
		t.Fatalf("Failed to generate LWE key pair: %v", err)
	}

	// Encrypt message
	message := []byte(testMessageLWE)
	ciphertext, err := EncryptLWE(keyPair.PublicKey, message)
	if err != nil {
		t.Fatalf("Failed to encrypt message: %v", err)
	}

	// Decrypt ciphertext
	plaintext, err := DecryptLWE(keyPair.PrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt ciphertext: %v", err)
	}

	// Compare decrypted message with original
	if string(plaintext) != string(message) {
		t.Errorf("Decrypted message does not match original: got %s, want %s", string(plaintext), string(message))
	}
}

// Test Ring-LWE key generation, encryption, and decryption
func TestRingLWEScheme(t *testing.T) {
	params := &RingLWEParams{
		N: nLWE,
		Q: big.NewInt(qLWE),
	}

	// Generate key pair
	keyPair, err := KeyGenRingLWE(params)
	if err != nil {
		t.Fatalf("Failed to generate Ring-LWE key pair: %v", err)
	}

	// Encrypt message
	message := []byte(testMessageRingLWE)
	ciphertext, err := EncryptRingLWE(params, keyPair.PublicKey, message)
	if err != nil {
		t.Fatalf("Failed to encrypt message: %v", err)
	}

	// Decrypt ciphertext
	plaintext, err := DecryptRingLWE(params, keyPair.PrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt ciphertext: %v", err)
	}

	// Compare decrypted message with original
	if string(plaintext) != string(message) {
		t.Errorf("Decrypted message does not match original: got %s, want %s", string(plaintext), string(message))
	}
}

// Test HashLWE function
func TestHashLWE(t *testing.T) {
	data := []byte("Test data for hashing")
	expectedHash := sha3.Sum256(data)
	hash := HashLWE(data)

	if !big.NewInt(0).SetBytes(hash).Cmp(big.NewInt(0).SetBytes(expectedHash[:])) == 0 {
		t.Errorf("Hash does not match expected value: got %x, want %x", hash, expectedHash)
	}
}
