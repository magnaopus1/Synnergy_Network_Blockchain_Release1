package smart_contract_deployment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// ContractDeployer is responsible for deploying smart contracts
type ContractDeployer struct {
	keystoreDir  string
	keystorePass string
	rpcURL       string
	mu           sync.Mutex
}

// NewContractDeployer creates a new ContractDeployer instance
func NewContractDeployer(keystoreDir, keystorePass, rpcURL string) *ContractDeployer {
	return &ContractDeployer{
		keystoreDir:  keystoreDir,
		keystorePass: keystorePass,
		rpcURL:       rpcURL,
	}
}

// DeployContract deploys the given compiled contract to the blockchain
func (cd *ContractDeployer) DeployContract(binaryPath string) (string, error) {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	privateKey, err := cd.getPrivateKey()
	if err != nil {
		return "", err
	}

	// Read the contract binary
	contractBin, err := ioutil.ReadFile(binaryPath)
	if err != nil {
		return "", fmt.Errorf("failed to read contract binary: %w", err)
	}

	// Create and sign the transaction
	rawTx, err := cd.createSignedTransaction(privateKey, contractBin)
	if err != nil {
		return "", fmt.Errorf("failed to create signed transaction: %w", err)
	}

	// Send the transaction
	txHash, err := cd.sendTransaction(rawTx)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %w", err)
	}

	// Wait for the transaction to be mined and get the contract address
	contractAddress, err := cd.waitForTransaction(txHash)
	if err != nil {
		return "", fmt.Errorf("failed to wait for transaction: %w", err)
	}

	return contractAddress, nil
}

func (cd *ContractDeployer) getPrivateKey() (*ecdsa.PrivateKey, error) {
	keyPath := filepath.Join(cd.keystoreDir, "keyfile")
	keyJSON, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyfile: %w", err)
	}

	key, err := decryptKey(keyJSON, cd.keystorePass)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	return key, nil
}

func decryptKey(keyJSON []byte, password string) (*ecdsa.PrivateKey, error) {
	var encryptedKey struct {
		Crypto struct {
			Ciphertext   string `json:"ciphertext"`
			Cipherparams struct {
				Iv string `json:"iv"`
			} `json:"cipherparams"`
			Kdf string `json:"kdf"`
			Kdfparams struct {
				Dklen int    `json:"dklen"`
				N     int    `json:"n"`
				R     int    `json:"r"`
				P     int    `json:"p"`
				Salt  string `json:"salt"`
			} `json:"kdfparams"`
			Mac string `json:"mac"`
		} `json:"crypto"`
	}

	err := json.Unmarshal(keyJSON, &encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal keyJSON: %w", err)
	}

	salt, err := hex.DecodeString(encryptedKey.Crypto.Kdfparams.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	derivedKey, err := scrypt.Key([]byte(password), salt, encryptedKey.Crypto.Kdfparams.N, encryptedKey.Crypto.Kdfparams.R, encryptedKey.Crypto.Kdfparams.P, encryptedKey.Crypto.Kdfparams.Dklen)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	cipherText, err := hex.DecodeString(encryptedKey.Crypto.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	iv, err := hex.DecodeString(encryptedKey.Crypto.Cipherparams.Iv)
	if err != nil {
		return nil, fmt.Errorf("failed to decode iv: %w", err)
	}

	plainText, err := aesDecrypt(cipherText, derivedKey[:16], iv)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	privateKey, err := cryptoToECDSA(plainText)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to ECDSA: %w", err)
	}

	return privateKey, nil
}

func aesDecrypt(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}

func cryptoToECDSA(privateKeyBytes []byte) (*ecdsa.PrivateKey, error) {
	privateKey, err := cryptoToECDSA(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func (cd *ContractDeployer) createSignedTransaction(privateKey *ecdsa.PrivateKey, contractBin []byte) (string, error) {
	nonce, err := cd.getTransactionCount(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to get transaction count: %w", err)
	}

	gasLimit := uint64(3000000)
	gasPrice := big.NewInt(20000000000)
	value := big.NewInt(0)

	tx := map[string]interface{}{
		"nonce":    fmt.Sprintf("0x%x", nonce),
		"gasPrice": fmt.Sprintf("0x%x", gasPrice),
		"gas":      fmt.Sprintf("0x%x", gasLimit),
		"value":    fmt.Sprintf("0x%x", value),
		"data":     fmt.Sprintf("0x%x", contractBin),
	}

	txHash := sha256.Sum256([]byte(fmt.Sprintf("%v", tx)))
	signature, err := signTransaction(txHash[:], privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	tx["r"], tx["s"], tx["v"] = signature.R, signature.S, signature.V
	rawTxBytes, err := json.Marshal(tx)
	if err != nil {
		return "", fmt.Errorf("failed to marshal transaction: %w", err)
	}

	return hex.EncodeToString(rawTxBytes), nil
}

func signTransaction(hash []byte, privateKey *ecdsa.PrivateKey) (signature struct{ R, S, V *big.Int }, err error) {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return signature, err
	}

	curveBits := privateKey.Curve.Params().BitSize

	// Adjust r and s to fit within the curve's bit size
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	rPadded := append(make([]byte, (curveBits+7)/8-len(rBytes)), rBytes...)
	sPadded := append(make([]byte, (curveBits+7)/8-len(sBytes)), sBytes...)

	v := 0 // Assuming chain ID is 0 for simplicity; this should be modified based on your network's chain ID

	return struct {
		R *big.Int
		S *big.Int
		V *big.Int
	}{new(big.Int).SetBytes(rPadded), new(big.Int).SetBytes(sPadded), big.NewInt(int64(v))}, nil
}

func (cd *ContractDeployer) sendTransaction(rawTx string) (string, error) {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_sendRawTransaction",
		"params":  []interface{}{rawTx},
		"id":      1,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON payload: %w", err)
	}

	req, err := http.NewRequest("POST", cd.rpcURL, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode JSON response: %w", err)
	}

	if result["error"] != nil {
		return "", fmt.Errorf("RPC error: %v", result["error"])
	}

	txHash, ok := result["result"].(string)
	if !ok {
		return "", fmt.Errorf("unexpected result type: %v", result["result"])
	}

	return txHash, nil
}

func (cd *ContractDeployer) waitForTransaction(txHash string) (string, error) {
	for {
		receipt, err := cd.getTransactionReceipt(txHash)
		if err != nil {
			return "", fmt.Errorf("failed to get transaction receipt: %w", err)
		}

		if receipt != nil {
			if receipt.Status == 0 {
				return "", fmt.Errorf("transaction failed")
			}
			return receipt.ContractAddress, nil
		}

		time.Sleep(time.Second)
	}
}

func (cd *ContractDeployer) getTransactionCount(privateKey *ecdsa.PrivateKey) (uint64, error) {
	address := privateKey.PublicKey // Modify this to obtain the correct address from the public key
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionCount",
		"params":  []interface{}{address, "latest"},
		"id":      1,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal JSON payload: %w", err)
	}

	req, err := http.NewRequest("POST", cd.rpcURL, bytes.NewBuffer(body))
	if err != nil {
		return 0, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode JSON response: %w", err)
	}

	if result["error"] != nil {
		return 0, fmt.Errorf("RPC error: %v", result["error"])
	}

	nonceStr, ok := result["result"].(string)
	if !ok {
		return 0, fmt.Errorf("unexpected result type: %v", result["result"])
	}

	nonce, err := strconv.ParseUint(strings.TrimPrefix(nonceStr, "0x"), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse nonce: %w", err)
	}

	return nonce, nil
}

func (cd *ContractDeployer) getTransactionReceipt(txHash string) (*Receipt, error) {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionReceipt",
		"params":  []interface{}{txHash},
		"id":      1,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON payload: %w", err)
	}

	req, err := http.NewRequest("POST", cd.rpcURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}

	if result["error"] != nil {
		return nil, fmt.Errorf("RPC error: %v", result["error"])
	}

	receiptData, ok := result["result"].(map[string]interface{})
	if !ok {
		return nil, nil // Transaction receipt not available yet
	}

	receipt := &Receipt{
		Status:          receiptData["status"].(uint64),
		ContractAddress: receiptData["contractAddress"].(string),
	}

	return receipt, nil
}

type Receipt struct {
	Status          uint64 `json:"status"`
	ContractAddress string `json:"contractAddress"`
}
