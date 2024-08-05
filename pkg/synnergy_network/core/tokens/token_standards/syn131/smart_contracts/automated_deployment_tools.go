package smart_contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn131/ledger"
)

// ContractDeploymentTool interface defines methods for automated contract deployment
type ContractDeploymentTool interface {
	DeployContract(template string, parameters map[string]interface{}) (string, error)
	GetDeploymentStatus(deploymentID string) (string, error)
}

// AutomatedDeploymentTool implements ContractDeploymentTool interface
type AutomatedDeploymentTool struct {
	DeploymentServiceURL string
	Ledger               ledger.Ledger
}

// NewAutomatedDeploymentTool creates a new instance of AutomatedDeploymentTool
func NewAutomatedDeploymentTool(deploymentServiceURL string, ledger ledger.Ledger) *AutomatedDeploymentTool {
	return &AutomatedDeploymentTool{
		DeploymentServiceURL: deploymentServiceURL,
		Ledger:               ledger,
	}
}

// DeployContract deploys a smart contract using a specified template and parameters
func (adt *AutomatedDeploymentTool) DeployContract(template string, parameters map[string]interface{}) (string, error) {
	deploymentRequest := map[string]interface{}{
		"template":   template,
		"parameters": parameters,
	}

	jsonData, err := json.Marshal(deploymentRequest)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(adt.DeploymentServiceURL+"/deploy", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("failed to deploy contract")
	}

	var result map[string]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	deploymentID, exists := result["deploymentID"]
	if !exists {
		return "", errors.New("deploymentID not returned")
	}

	// Log the deployment in the ledger
	err = adt.Ledger.LogDeployment(deploymentID, template, parameters)
	if err != nil {
		return "", err
	}

	return deploymentID, nil
}

// GetDeploymentStatus retrieves the status of a deployed contract using deploymentID
func (adt *AutomatedDeploymentTool) GetDeploymentStatus(deploymentID string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("%s/status/%s", adt.DeploymentServiceURL, deploymentID))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("failed to get deployment status")
	}

	var result map[string]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	status, exists := result["status"]
	if !exists {
		return "", errors.New("status not returned")
	}

	return status, nil
}

// Ledger interface for logging deployments
type Ledger interface {
	LogDeployment(deploymentID, template string, parameters map[string]interface{}) error
}

// ExampleLedger is an example implementation of the Ledger interface
type ExampleLedger struct {
	deployments map[string]DeploymentRecord
}

// DeploymentRecord represents a record of a contract deployment
type DeploymentRecord struct {
	DeploymentID string
	Template     string
	Parameters   map[string]interface{}
	Timestamp    time.Time
}

// NewExampleLedger creates a new instance of ExampleLedger
func NewExampleLedger() *ExampleLedger {
	return &ExampleLedger{
		deployments: make(map[string]DeploymentRecord),
	}
}

// LogDeployment logs a deployment in the ledger
func (el *ExampleLedger) LogDeployment(deploymentID, template string, parameters map[string]interface{}) error {
	el.deployments[deploymentID] = DeploymentRecord{
		DeploymentID: deploymentID,
		Template:     template,
		Parameters:   parameters,
		Timestamp:    time.Now(),
	}
	return nil
}

// GetDeploymentRecord retrieves a deployment record from the ledger
func (el *ExampleLedger) GetDeploymentRecord(deploymentID string) (DeploymentRecord, error) {
	record, exists := el.deployments[deploymentID]
	if !exists {
		return DeploymentRecord{}, errors.New("deployment record not found")
	}
	return record, nil
}
