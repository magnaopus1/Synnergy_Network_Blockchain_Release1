package web3_integration_test

import (
    "context"
    "fmt"
    "log"
    "math/big"
    "os"
    "testing"
    "time"

    "Synthron-blockchain/pkg/client" // Local blockchain client
    "Synthron-blockchain/pkg/types"  // Local types for transactions
)

const (
    rpcURL           = "http://localhost:3000"
    privateKeyHex    = "YOUR_PRIVATE_KEY_HEX"
    contractABI      = `YOUR_CONTRACT_ABI`
    contractAddress  = "YOUR_CONTRACT_ADDRESS"
)

var (
    blockchainClient *client.Client
)

func TestMain(m *testing.M) {
    var err error
    blockchainClient, err = client.Dial(rpcURL)
    if err != nil {
        log.Fatalf("Failed to connect to blockchain node: %v", err)
    }

    exitCode := m.Run()
    blockchainClient.Close()
    os.Exit(exitCode)
}

func TestGetLatestBlockNumber(t *testing.T) {
    blockNumber, err := blockchainClient.GetLatestBlockNumber(context.Background())
    if err != nil {
        t.Fatalf("Failed to get latest block number: %v", err)
    }
    fmt.Printf("Latest Block Number: %v\n", blockNumber)
}

func TestSendTransaction(t *testing.T) {
    gasPrice := big.NewInt(1000000000) // Example gas price
    nonce, err := blockchainClient.GetNonce("YOUR_SENDER_ADDRESS", context.Background())
    if err != nil {
        t.Fatalf("Failed to get sender's nonce: %v", err)
    }

    tx := types.NewTransaction(nonce, "YOUR_RECIPIENT_ADDRESS", big.NewInt(1), gasPrice, big.NewInt(21000), nil)
    signedTx, err := blockchainClient.SignTransaction(tx, privateKeyHex)
    if err != nil {
        t.Fatalf("Failed to sign transaction: %v", err)
    }

    err = blockchainClient.SendTransaction(context.Background(), signedTx)
    if err != nil {
        t.Fatalf("Failed to send transaction: %v", err)
    }

    fmt.Println("Transaction sent successfully")
}

func TestContractInteraction(t *testing.T) {
    contract, err := blockchainClient.NewContract(contractABI, contractAddress, context.Background())
    if err != nil {
        t.Fatalf("Failed to create contract instance: %v", err)
    }

    result, err := contract.CallMethod(context.Background(), "YOUR_METHOD_NAME", "arg1", "arg2")
    if err != nil {
        t.Fatalf("Failed to call contract method: %v", err)
    }

    fmt.Printf("Contract Method Result: %v\n", result)
}

// Add more test cases for specific contract interactions and event listening as needed.
