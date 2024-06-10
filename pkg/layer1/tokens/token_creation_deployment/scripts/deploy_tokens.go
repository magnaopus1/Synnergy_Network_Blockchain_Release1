package scripts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"synthron-blockchain/pkg/Token_Creation_Deployment/config"
)

type ContractDetails struct {
	Language   string `json:"language"`
	SourceCode string `json:"sourceCode"`
	ABI        string `json:"abi"`
	Binary     string `json:"binary"`
}

type DeploymentResponse struct {
	TransactionID   string `json:"transactionId"`
	ContractAddress string `json:"contractAddress"`
	Error           string `json:"error,omitempty"`
}

func main() {
	cfg := config.NewNetworkConfig()
	contractsPath := "./contracts" // Local directory for contracts

	files, err := ioutil.ReadDir(contractsPath)
	if err != nil {
		log.Fatalf("Failed to read contracts directory: %v", err)
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") { // Expect JSON format for contracts
			deployContract(cfg, filepath.Join(contractsPath, file.Name()))
		}
	}
}

func deployContract(cfg *config.NetworkConfig, contractPath string) {
	content, err := ioutil.ReadFile(contractPath)
	if err != nil {
		log.Printf("Error reading contract file %s: %v", contractPath, err)
		return
	}

	var contractDetails ContractDetails
	if err := json.Unmarshal(content, &contractDetails); err != nil {
		log.Printf("Error parsing contract details in %s: %v", contractPath, err)
		return
	}

	if contractDetails.Language == "Solidity" || contractDetails.Language == "Rust" {
		if err := compileContract(&contractDetails); err != nil {
			log.Printf("Failed to compile contract %s: %v", contractPath, err)
			return
		}
	}

	response, err := deployContractHTTP(cfg.NodeURL, &contractDetails)
	if err != nil {
		log.Printf("Error deploying contract %s: %v", contractPath, err)
		return
	}

	log.Printf("Deployed contract %s successfully. Transaction ID: %s, Address: %s",
		contractPath, response.TransactionID, response.ContractAddress)
}

func compileContract(details *ContractDetails) error {
	log.Printf("Compiling %s contract...", details.Language)
	// Compilation logic will be implemented here
	// This is a placeholder for actual compilation logic
	details.Binary = "compiled_binary_here"
	return nil
}

func deployContractHTTP(nodeURL string, details *ContractDetails) (*DeploymentResponse, error) {
	deployURL := fmt.Sprintf("%s/api/v1/deployContract", nodeURL)
	data, err := json.Marshal(details)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal contract details: %v", err)
	}

	resp, err := http.Post(deployURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to send deployment request: %v", err)
	}
	defer resp.Body.Close()

	var deploymentResponse DeploymentResponse
	if err := json.Unmarshal(ioutil.ReadAll(resp.Body), &deploymentResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal deployment response: %v", err)
	}

	return &deploymentResponse, nil
}
