package smart_contract_deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ContractDeployment defines the necessary information for deploying a smart contract
type ContractDeployment struct {
	NodeURL     string
	PrivateKey  string
	ContractBin string
	ContractABI string
	GasLimit    uint64
	GasPrice    uint64
	Compiler    CompilerType
}

// NewContractDeployment initializes a new ContractDeployment
func NewContractDeployment(nodeURL, privateKey, contractBin, contractABI string, gasLimit, gasPrice uint64, compiler CompilerType) *ContractDeployment {
	return &ContractDeployment{
		NodeURL:     nodeURL,
		PrivateKey:  privateKey,
		ContractBin: contractBin,
		ContractABI: contractABI,
		GasLimit:    gasLimit,
		GasPrice:    gasPrice,
		Compiler:    compiler,
	}
}

// Deploy deploys the smart contract to the blockchain
func (cd *ContractDeployment) Deploy() (string, error) {
	// Validate input
	if cd.NodeURL == "" || cd.PrivateKey == "" || cd.ContractBin == "" || cd.ContractABI == "" {
		return "", errors.New("missing required deployment parameters")
	}

	// Compile contract if needed
	if cd.Compiler != "" {
		err := cd.compileContract()
		if err != nil {
			return "", fmt.Errorf("failed to compile contract: %v", err)
		}
	}

	// Deploy the contract
	txHash, err := cd.sendTransaction()
	if err != nil {
		return "", fmt.Errorf("failed to deploy contract: %v", err)
	}

	log.Printf("Contract deployed successfully, transaction hash: %s", txHash)
	return txHash, nil
}

// compileContract compiles the smart contract using the specified compiler
func (cd *ContractDeployment) compileContract() error {
	log.Printf("Compiling contract with %s...", cd.Compiler)

	outputFile := strings.TrimSuffix(cd.ContractBin, filepath.Ext(cd.ContractBin)) + ".bin"

	args := []string{
		"--bin",
		"--abi",
		"--overwrite",
		"-o", filepath.Dir(cd.ContractBin),
	}

	if cd.Compiler == SolidityCompiler {
		args = append(args, cd.ContractBin)
	} else if cd.Compiler == VyperCompiler {
		args = append(args, cd.ContractBin)
	} else {
		return fmt.Errorf("unsupported compiler: %s", cd.Compiler)
	}

	cmd := exec.Command(string(cd.Compiler), args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("compilation failed: %v - output: %s", err, out.String())
	}

	log.Printf("Compiled contract successfully to %s", outputFile)
	cd.ContractBin = outputFile
	return nil
}

// sendTransaction sends the transaction to deploy the contract
func (cd *ContractDeployment) sendTransaction() (string, error) {
	log.Printf("Sending transaction to deploy contract...")

	// Prepare the deployment script
	deployScript := fmt.Sprintf(`
web3 = require('web3');
fs = require('fs');
web3 = new web3(new web3.providers.HttpProvider('%s'));
contractABI = JSON.parse(fs.readFileSync('%s'));
contractBin = fs.readFileSync('%s').toString();
contract = new web3.eth.Contract(contractABI);
account = web3.eth.accounts.privateKeyToAccount('%s');
web3.eth.accounts.wallet.add(account);
web3.eth.defaultAccount = account.address;

deploy = async () => {
    contract.deploy({
        data: '0x' + contractBin,
    })
    .send({
        from: account.address,
        gas: %d,
        gasPrice: '%d'
    })
    .on('transactionHash', function(hash){
        console.log(hash);
    })
    .on('receipt', function(receipt){
        console.log(receipt.contractAddress);
    })
    .on('confirmation', function(confirmationNumber, receipt){
        console.log(confirmationNumber);
    })
    .on('error', function(error){
        console.error(error);
    });
};

deploy();
`, cd.NodeURL, cd.ContractABI, cd.ContractBin, cd.PrivateKey, cd.GasLimit, cd.GasPrice)

	// Write the script to a temporary file
	scriptFile, err := os.CreateTemp("", "deploy_contract_*.js")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary script file: %v", err)
	}
	defer os.Remove(scriptFile.Name())

	_, err = scriptFile.WriteString(deployScript)
	if err != nil {
		return "", fmt.Errorf("failed to write deploy script: %v", err)
	}
	scriptFile.Close()

	// Execute the script
	cmd := exec.Command("node", scriptFile.Name())
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err = cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to execute deploy script: %v - output: %s", err, out.String())
	}

	outputLines := strings.Split(out.String(), "\n")
	if len(outputLines) < 1 {
		return "", errors.New("unexpected output from deployment script")
	}

	txHash := outputLines[0]
	return txHash, nil
}
