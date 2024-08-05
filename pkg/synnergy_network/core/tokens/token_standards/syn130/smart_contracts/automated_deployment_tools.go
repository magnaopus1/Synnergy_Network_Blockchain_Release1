package smart_contracts

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// DeploymentTool is a structure to manage the deployment of smart contracts
type DeploymentTool struct {
	Network       string
	ContractPath  string
	DeploymentCmd string
}

// NewDeploymentTool creates a new instance of DeploymentTool
func NewDeploymentTool(network, contractPath, deploymentCmd string) *DeploymentTool {
	return &DeploymentTool{
		Network:       network,
		ContractPath:  contractPath,
		DeploymentCmd: deploymentCmd,
	}
}

// DeployContract deploys the smart contract to the specified network
func (dt *DeploymentTool) DeployContract(params map[string]string) (string, error) {
	cmdArgs := []string{dt.DeploymentCmd, dt.ContractPath, dt.Network}
	for key, value := range params {
		cmdArgs = append(cmdArgs, fmt.Sprintf("--%s=%s", key, value))
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return "", errors.New(out.String())
	}

	return out.String(), nil
}

// ValidateContract ensures the contract's syntax and structure are correct before deployment
func (dt *DeploymentTool) ValidateContract() error {
	cmd := exec.Command("solc", "--optimize", "--bin", dt.ContractPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return errors.New(out.String())
	}

	if strings.Contains(out.String(), "Error") {
		return errors.New("validation failed: " + out.String())
	}

	return nil
}

// GenerateDeploymentScript creates a deployment script for automated CI/CD integration
func (dt *DeploymentTool) GenerateDeploymentScript(scriptPath string, params map[string]string) error {
	script := fmt.Sprintf("#!/bin/bash\n\n%s %s %s", dt.DeploymentCmd, dt.ContractPath, dt.Network)
	for key, value := range params {
		script += fmt.Sprintf(" --%s=%s", key, value)
	}

	return os.WriteFile(scriptPath, []byte(script), 0755)
}

// TestContractDeployment performs a test deployment to ensure everything works as expected
func (dt *DeploymentTool) TestContractDeployment(params map[string]string) (string, error) {
	testNetwork := "testnet"
	cmdArgs := []string{dt.DeploymentCmd, dt.ContractPath, testNetwork}
	for key, value := range params {
		cmdArgs = append(cmdArgs, fmt.Sprintf("--%s=%s", key, value))
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return "", errors.New(out.String())
	}

	return out.String(), nil
}

// MonitorDeployment monitors the deployment process and provides real-time updates
func (dt *DeploymentTool) MonitorDeployment() error {
	cmd := exec.Command("tail", "-f", "/var/log/deployment.log")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		return err
	}

	err = cmd.Wait()
	if err != nil {
		return err
	}

	return nil
}

// RollbackDeployment rolls back the deployment in case of any issues
func (dt *DeploymentTool) RollbackDeployment() error {
	cmd := exec.Command("rollback", dt.Network)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return errors.New(out.String())
	}

	return nil
}

// SetupCIIntegration sets up CI/CD pipeline for automated contract deployment
func (dt *DeploymentTool) SetupCIIntegration(ciConfigPath string, params map[string]string) error {
	ciConfig := fmt.Sprintf("pipeline:\n  stages:\n    - deploy\n  deploy:\n    stage: deploy\n    script:\n      - %s %s %s", dt.DeploymentCmd, dt.ContractPath, dt.Network)
	for key, value := range params {
		ciConfig += fmt.Sprintf(" --%s=%s", key, value)
	}

	return os.WriteFile(ciConfigPath, []byte(ciConfig), 0644)
}
