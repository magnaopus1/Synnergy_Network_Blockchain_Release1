package syn_wallet

import (
	"encoding/hex"
	"testing"
)

func TestNewSynWallet(t *testing.T) {
	wallet, err := NewSynWallet()
	if err != nil {
		t.Fatalf("Error creating a new SynWallet: %v", err)
	}

	if wallet == nil {
		t.Fatal("NewSynWallet returned nil wallet")
	}

	if wallet.GetAddress().Hex() == "" {
		t.Fatal("NewSynWallet generated an empty wallet address")
	}
}

func TestSignTransaction(t *testing.T) {
	wallet, err := NewSynWallet()
	if err != nil {
		t.Fatalf("Error creating a new SynWallet: %v", err)
	}

	txData := []byte("Transaction data to sign")
	signature, err := wallet.SignTransaction(txData)
	if err != nil {
		t.Fatalf("Error signing transaction: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("Empty transaction signature")
	}
}

func TestExportAndLoadWallet(t *testing.T) {
	// Create a new Synthron wallet
	wallet, err := NewSynWallet()
	if err != nil {
		t.Fatalf("Error creating a new SynWallet: %v", err)
	}

	password := "your_password" // Replace with your secure password

	// Export the wallet's private key
	privateKeyStr, err := wallet.ExportPrivateKey(password)
	if err != nil {
		t.Fatalf("Error exporting private key: %v", err)
	}

	// Load the wallet from the exported private key
	loadedWallet, err := LoadWalletFromPrivateKey(string(privateKeyStr), password)
	if err != nil {
		t.Fatalf("Error loading wallet from private key: %v", err)
	}

	if wallet.GetAddress() != loadedWallet.GetAddress() {
		t.Fatal("Loaded wallet address doesn't match the original wallet")
	}
}

func TestLoadWalletFromInvalidPrivateKey(t *testing.T) {
	invalidPrivateKey := "invalid_private_key"
	password := "your_password" // Replace with your secure password

	_, err := LoadWalletFromPrivateKey(invalidPrivateKey, password)
	if err == nil {
		t.Fatal("Expected an error when loading an invalid private key, but got none")
	}
}

func TestMain(m *testing.M) {
	// Perform any setup or teardown actions if needed
	m.Run()
}
