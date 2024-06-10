package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"synthron-blockchain/pkg/Token_Creation_Deployment/config"
	"synthron-blockchain/pkg/Token_Creation_Deployment/scripts"
)

// TestTokenDeploymentAndVerification simulates the deployment and verification of a token contract.
func TestTokenDeploymentAndVerification(t *testing.T) {
	cfg := config.NewNetworkConfig()
	server := mockBlockchainServer()
	defer server.Close()

	cfg.NodeURL = server.URL // Override the node URL to use the mock server
	contractDetails := prepareContractDetails()

	// Simulate deployment
	deployResponse, err := scripts.DeployContractHTTP(cfg.NodeURL, contractDetails)
	if err != nil {
		t.Fatalf("Deployment failed: %v", err)
	}
	if deployResponse.Error != "" {
		t.Fatalf("Deployment failed with error: %s", deployResponse.Error)
	}

	// Simulate verification
	verifyResponse, err := scripts.VerifyContractHTTP(cfg.NodeURL, deployResponse.ContractAddress)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if !verifyResponse.IsVerified {
		t.Errorf("Verification failed: %s", verifyResponse.Message)
	}
}

// mockBlockchainServer creates an HTTP server that simulates blockchain responses for deployment and verification.
func mockBlockchainServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var response interface{}

		switch r.URL.Path {
		case "/api/v1/deployContract":
			response = scripts.DeploymentResponse{
				TransactionID:   "tx_123456",
				ContractAddress: "0xContractAddress",
			}
		case "/api/v1/verifyContract":
			response = scripts.VerificationResponse{
				IsVerified: true,
				Message:    "Contract is verified successfully",
			}
		default:
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	return httptest.NewServer(handler)
}

// prepareContractDetails prepares a dummy contract detail for testing.
func prepareContractDetails() *scripts.ContractDetails {
	return &scripts.ContractDetails{
		Language:   "Solidity",
		SourceCode: "pragma solidity ^0.5.0; contract Test { }",
		ABI:        "[]",
		Binary:     "0x600...",
	}
}

// DeployContractHTTP and VerifyContractHTTP are assumed to be part of the scripts package.
