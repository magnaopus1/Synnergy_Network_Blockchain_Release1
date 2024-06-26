package gateway_node_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synthron_blockchain/blockchain"
	"github.com/synthron_blockchain/pkg/layer0/node/gateway_node"
)

func setupTestNode(t *testing.T) *gateway_node.GatewayNode {
	privateKey := make([]byte, 32)
	_, err := rand.Read(privateKey)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	publicKey := make([]byte, 32)
	_, err = rand.Read(publicKey)
	if err != nil {
		t.Fatalf("Failed to generate public key: %v", err)
	}

	node, err := gateway_node.NewGatewayNode("test-node", "127.0.0.1:8080", privateKey, publicKey)
	if err != nil {
		t.Fatalf("Failed to create GatewayNode: %v", err)
	}

	return node
}

func TestGatewayNode_StartStop(t *testing.T) {
	node := setupTestNode(t)

	go func() {
		err := node.Start()
		if err != nil && err != context.Canceled {
			t.Fatalf("Failed to start GatewayNode: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)

	node.Stop()
}

func TestGatewayNode_EncryptDecryptData(t *testing.T) {
	node := setupTestNode(t)

	data := []byte("test data")
	encryptedData, err := node.EncryptData(data)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	decryptedData, err := node.DecryptData(encryptedData)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	if !bytes.Equal(data, decryptedData) {
		t.Fatalf("Decrypted data does not match original data. Got %v, expected %v", decryptedData, data)
	}
}

func TestGatewayNode_AuthenticateVerify(t *testing.T) {
	node := setupTestNode(t)

	password := "securepassword"
	hash, err := node.Authenticate(password)
	if err != nil {
		t.Fatalf("Failed to authenticate: %v", err)
	}

	if !node.VerifyAuthentication(password, hash) {
		t.Fatalf("Failed to verify authentication")
	}

	if node.VerifyAuthentication("wrongpassword", hash) {
		t.Fatalf("Authentication verification should fail for incorrect password")
	}
}

func TestGatewayNode_Integration(t *testing.T) {
	node := setupTestNode(t)

	// Simulate integration with an external data source
	err := node.IntegrateExternalData("https://api.externaldata.com")
	if err != nil {
		t.Fatalf("Failed to integrate external data: %v", err)
	}
}

func TestGatewayNode_PerformSecurityAudit(t *testing.T) {
	node := setupTestNode(t)

	err := node.PerformSecurityAudit()
	if err != nil {
		t.Fatalf("Failed to perform security audit: %v", err)
	}
}

func TestGatewayNode_SendTransaction(t *testing.T) {
	node := setupTestNode(t)

	tx := &blockchain.Transaction{
		ID:     "tx1",
		Amount: 1000,
	}

	err := node.SendTransaction(tx)
	if err != nil {
		t.Fatalf("Failed to send transaction: %v", err)
	}
}

func TestGatewayNode_QueryBlockchain(t *testing.T) {
	node := setupTestNode(t)

	query := &blockchain.Query{
		Key: "some-key",
	}

	response, err := node.QueryBlockchain(query)
	if err != nil {
		t.Fatalf("Failed to query blockchain: %v", err)
	}

	expectedResponse := &blockchain.Response{
		Data: "query response",
	}

	if response.Data != expectedResponse.Data {
		t.Fatalf("Query response mismatch. Got %v, expected %v", response.Data, expectedResponse.Data)
	}
}

func TestGatewayNode_EnhancedTransactionRouting(t *testing.T) {
	node := setupTestNode(t)

	err := node.EnhanceTransactionRouting()
	if err != nil {
		t.Fatalf("Failed to enhance transaction routing: %v", err)
	}
}
