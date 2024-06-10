package main

import (
    "context"
    "crypto/ecdsa"
    "fmt"
    "log"
    "math/big"
    "os"

    "Synthron-blockchain/pkg/blockchain/address"
    "Synthron-blockchain/pkg/client"
    "Synthron-blockchain/pkg/crypto"
    "Synthron-blockchain/pkg/types"
)

const (
    rpcURL          = "http://localhost:3000" // Your local development RPC URL
    privateKeyHex   = "YOUR_PRIVATE_KEY_HEX"  // Hexadecimal format of your private key
    contractABI     = `YOUR_CONTRACT_ABI_JSON` // Contract ABI JSON
    contractAddress = "YOUR_CONTRACT_ADDRESS"  // Contract address
)

var (
    blockchainClient *client.BlockchainClient
    auth             *types.AuthOptions
    contract         *Contract // Your specific contract type
)

func init() {
    var err error
    blockchainClient, err = client.Dial(rpcURL) // Assuming a Dial function in your local client package
    if err != nil {
        log.Fatalf("Failed to connect to the blockchain node: %v", err)
    }

    privateKey, err := crypto.HexToECDSA(privateKeyHex)
    if err != nil {
        log.Fatalf("Failed to decode private key: %v", err)
    }

    auth = types.NewAuthOptions(privateKey) // Assuming a constructor for auth options

    contract, err = NewContract(contractAddress, blockchainClient) // Assuming a constructor for your contract
    if err != nil {
        log.Fatalf("Failed to instantiate the contract: %v", err)
    }
}

func getLatestBlockNumber() (*big.Int, error) {
    blockNumber, err := blockchainClient.BlockNumber(context.Background())
    if err != nil {
        return nil, err
    }
    return big.NewInt(int64(blockNumber)), nil
}

func sendTransaction(toAddress string, value *big.Int) (*types.Transaction, error) {
    tx, err := types.NewTransaction(auth, toAddress, value) // Assuming a simplified transaction creation
    if err != nil {
        return nil, err
    }

    err = blockchainClient.SendTransaction(context.Background(), tx)
    if err != nil {
        return nil, err
    }

    return tx, nil
}

func callContractMethod(methodName string, args ...interface{}) (interface{}, error) {
    result, err := contract.CallMethod(context.Background(), methodName, args...)
    if err != nil {
        return nil, err
    }

    return result, nil
}

func main() {
    latestBlockNumber, err := getLatestBlockNumber()
    if err != nil {
        log.Fatalf("Failed to get latest block number: %v", err)
    }
    fmt.Printf("Latest Block Number: %s\n", latestBlockNumber.String())

    toAddress := "YOUR_RECIPIENT_ADDRESS" // Target address
    value := big.NewInt(1e18) // Example value in Wei (1 ETH)
    tx, err := sendTransaction(toAddress, value)
    if err != nil {
        log.Fatalf("Failed to send transaction: %v", err)
    }

    fmt.Printf("Transaction Hash: %s\n", tx.Hash())

    // Call a contract method
    methodName := "MethodName"
    result, err := callContractMethod(methodName, "arg1", "arg2") // Example args
    if err != nil {
        log.Fatalf("Failed to call contract method: %v", err)
    }

    fmt.Printf("Contract Method Result: %+v\n", result)
}
