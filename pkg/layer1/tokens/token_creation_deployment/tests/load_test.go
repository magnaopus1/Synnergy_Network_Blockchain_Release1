package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "sync"
    "testing"
    "time"

    "synthron-blockchain/pkg/Token_Creation_Deployment/config"
    "synthron-blockchain/pkg/Token_Creation_Deployment/scripts"
)

// TestTokenDeploymentLoad tests the load capacity of the token deployment system.
func TestTokenDeploymentLoad(t *testing.T) {
    cfg := config.NewNetworkConfig()
    cfg.NodeURL = "http://localhost:3000" // Ensure this points to your test blockchain node

    // Prepare the contract details
    contractDetails := &scripts.ContractDetails{
        Language:   "Solidity",
        SourceCode: "pragma solidity ^0.5.0; contract LoadTest { }",
        ABI:        "[]",
        Binary:     "0x600...",
    }

    // Set the number of concurrent deployments
    concurrentDeployments := 100

    var wg sync.WaitGroup
    wg.Add(concurrentDeployments)

    start := time.Now()

    for i := 0; i < concurrentDeployments; i++ {
        go func() {
            defer wg.Done()
            // Simulate deployment
            response, err := deployContract(cfg, contractDetails)
            if err != nil {
                t.Error("Error deploying contract:", err)
            } else {
                fmt.Println("Deployed contract successfully: Transaction ID:", response.TransactionID)
            }
        }()
    }

    wg.Wait()
    duration := time.Since(start)
    fmt.Println("Total time for", concurrentDeployments, "deployments:", duration)
}

// deployContract simulates deploying a contract to the blockchain
func deployContract(cfg *config.NetworkConfig, details *scripts.ContractDetails) (*scripts.DeploymentResponse, error) {
    deployURL := fmt.Sprintf("%s/api/v1/deployContract", cfg.NodeURL)
    data, err := json.Marshal(details)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal contract details: %v", err)
    }

    resp, err := http.Post(deployURL, "application/json", bytes.NewBuffer(data))
    if err != nil {
        return nil, fmt.Errorf("failed to send deployment request: %v", err)
    }
    defer resp.Body.Close()

    var deploymentResponse scripts.DeploymentResponse
    if err := json.NewDecoder(resp.Body).Decode(&deploymentResponse); err != nil {
        return nil, fmt.Errorf("failed to decode deployment response: %v", err)
    }

    return &deploymentResponse, nil
}
