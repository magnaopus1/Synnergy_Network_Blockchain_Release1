package multivariate_polynomials

import (
	"bytes"
	"testing"
)

// TestGenerateKeyPair tests the key pair generation
func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	if keyPair.PublicKey == nil || keyPair.PrivateKey == nil {
		t.Fatalf("Key pair is not properly generated")
	}
}

// TestEncryptionDecryption tests the encryption and decryption process
func TestEncryptionDecryption(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("test message 1234")
	ciphertext, err := Encrypt(keyPair.PublicKey, message)
	if err != nil {
		t.Fatalf("Failed to encrypt message: %v", err)
	}

	plaintext, err := Decrypt(keyPair.PrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt ciphertext: %v", err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatalf("Decrypted message does not match original, got %s, want %s", plaintext, message)
	}
}

// TestSignVerify tests the signing and verification process
func TestSignVerify(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("test message 1234")
	signature, err := Sign(keyPair.PrivateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	valid, err := Verify(keyPair.PublicKey, message, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if !valid {
		t.Fatalf("Signature verification failed")
	}
}

// TestInvalidSignature tests verification with an invalid signature
func TestInvalidSignature(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("test message 1234")
	signature, err := Sign(keyPair.PrivateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Modify the signature to be invalid
	signature[0] ^= 0xFF

	valid, err := Verify(keyPair.PublicKey, message, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if valid {
		t.Fatalf("Invalid signature verification passed")
	}
}

// TestKeyGenerationAndUsage tests key generation and usage in encryption and signing
func TestKeyGenerationAndUsage(t *testing.T) {
	keyPair1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair 1: %v", err)
	}

	keyPair2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair 2: %v", err)
	}

	message := []byte("test message 1234")

	// Encrypt with keyPair1 public key
	ciphertext, err := Encrypt(keyPair1.PublicKey, message)
	if err != nil {
		t.Fatalf("Failed to encrypt message with keyPair1: %v", err)
	}

	// Decrypt with keyPair1 private key
	plaintext, err := Decrypt(keyPair1.PrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt ciphertext with keyPair1: %v", err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatalf("Decrypted message does not match original for keyPair1, got %s, want %s", plaintext, message)
	}

	// Sign with keyPair2 private key
	signature, err := Sign(keyPair2.PrivateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message with keyPair2: %v", err)
	}

	// Verify with keyPair2 public key
	valid, err := Verify(keyPair2.PublicKey, message, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature with keyPair2: %v", err)
	}

	if !valid {
		t.Fatalf("Signature verification failed for keyPair2")
	}
}
