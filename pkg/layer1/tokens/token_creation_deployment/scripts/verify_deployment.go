package scripts

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"bytes"
	"synthron-blockchain/pkg/Token_Creation_Deployment/config"
)

type ContractVerificationRequest struct {
	ContractAddress string `json:"contractAddress"`
}

type VerificationResponse struct {
	IsVerified bool   `json:"isVerified"`
	Message    string `json:"message"`
}

func main() {
	cfg := config.NewNetworkConfig()
	deploymentsPath := "./deployments" // Directory where deployment records are stored

	files, err := ioutil.ReadDir(deploymentsPath)
	if err != nil {
		log.Fatalf("Failed to read deployments directory: %v", err)
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") { // Expect JSON for deployment details
			verifyDeployment(cfg, filepath.Join(deploymentsPath, file.Name()))
		}
	}
}

func verifyDeployment(cfg *config.NetworkConfig, deploymentFilePath string) {
	content, err := ioutil.ReadFile(deploymentFilePath)
	if err != nil {
		log.Printf("Error reading deployment file %s: %v", deploymentFilePath, err)
		return
	}

	var request ContractVerificationRequest
	if err := json.Unmarshal(content, &request); err != nil {
		log.Printf("Error parsing deployment details in %s: %v", deploymentFilePath, err)
		return
	}

	response, err := verifyContractHTTP(cfg.NodeURL, &request)
	if err != nil {
		log.Printf("Error verifying contract from file %s: %v", deploymentFilePath, err)
		return
	}

	if response.IsVerified {
		log.Printf("Verification successful for contract at %s: %s", request.ContractAddress, response.Message)
	} else {
		log.Printf("Verification failed for contract at %s: %s", request.ContractAddress, response.Message)
	}
}

func verifyContractHTTP(nodeURL string, request *ContractVerificationRequest) (*VerificationResponse, error) {
	verifyURL := fmt.Sprintf("%s/api/v1/verifyContract", nodeURL)
	data, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verification request: %v", err)
	}

	resp, err := http.Post(verifyURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to send verification request: %v", err)
	}
	defer resp.Body.Close()

	var verificationResponse VerificationResponse
	if err := json.Unmarshal(ioutil.ReadAll(resp.Body), &verificationResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal verification response: %v", err)
	}

	return &verificationResponse, nil
}
