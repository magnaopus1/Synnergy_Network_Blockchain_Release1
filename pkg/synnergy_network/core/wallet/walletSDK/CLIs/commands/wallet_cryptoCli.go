package commands

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/spf13/cobra"
	"synnergy_network_blockchain/pkg/synnergy_network/core/wallet/crypto"
)

var (
	passphrase  string
	inputFile   string
	outputFile  string
	privateKeyFile string
	publicKeyFile  string
	signatureFile string
)

func init() {
	rootCmd.AddCommand(generateKeyPairCmd)
	rootCmd.AddCommand(encryptDataCmd)
	rootCmd.AddCommand(decryptDataCmd)
	rootCmd.AddCommand(signDataCmd)
	rootCmd.AddCommand(verifySignatureCmd)
}

var rootCmd = &cobra.Command{
	Use:   "walletCryptoCli",
	Short: "CLI for wallet cryptographic operations",
	Long:  "CLI for performing various cryptographic operations within the Synnergy Network Blockchain wallet.",
}

var generateKeyPairCmd = &cobra.Command{
	Use:   "generateKeyPair",
	Short: "Generate a new ECDSA key pair",
	Run: func(cmd *cobra.Command, args []string) {
		privateKey, err := crypto.GenerateKeyPair()
		if err != nil {
			log.Fatalf("Error generating key pair: %v", err)
		}

		privateKeyBytes := privateKey.D.Bytes()
		publicKeyBytes := append(privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes()...)

		err = ioutil.WriteFile(privateKeyFile, []byte(hex.EncodeToString(privateKeyBytes)), 0600)
		if err != nil {
			log.Fatalf("Error writing private key to file: %v", err)
		}

		err = ioutil.WriteFile(publicKeyFile, []byte(hex.EncodeToString(publicKeyBytes)), 0600)
		if err != nil {
			log.Fatalf("Error writing public key to file: %v", err)
		}

		fmt.Println("Key pair generated and saved successfully.")
	},
}

var encryptDataCmd = &cobra.Command{
	Use:   "encryptData",
	Short: "Encrypt data using AES-256-GCM",
	Run: func(cmd *cobra.Command, args []string) {
		data, err := ioutil.ReadFile(inputFile)
		if err != nil {
			log.Fatalf("Error reading input file: %v", err)
		}

		encryptedData, err := crypto.EncryptData(data, passphrase)
		if err != nil {
			log.Fatalf("Error encrypting data: %v", err)
		}

		err = ioutil.WriteFile(outputFile, encryptedData, 0600)
		if err != nil {
			log.Fatalf("Error writing encrypted data to file: %v", err)
		}

		fmt.Println("Data encrypted and saved successfully.")
	},
}

var decryptDataCmd = &cobra.Command{
	Use:   "decryptData",
	Short: "Decrypt data using AES-256-GCM",
	Run: func(cmd *cobra.Command, args []string) {
		data, err := ioutil.ReadFile(inputFile)
		if err != nil {
			log.Fatalf("Error reading input file: %v", err)
		}

		decryptedData, err := crypto.DecryptData(data, passphrase)
		if err != nil {
			log.Fatalf("Error decrypting data: %v", err)
		}

		err = ioutil.WriteFile(outputFile, decryptedData, 0600)
		if err != nil {
			log.Fatalf("Error writing decrypted data to file: %v", err)
		}

		fmt.Println("Data decrypted and saved successfully.")
	},
}

var signDataCmd = &cobra.Command{
	Use:   "signData",
	Short: "Sign data using ECDSA",
	Run: func(cmd *cobra.Command, args []string) {
		data, err := ioutil.ReadFile(inputFile)
		if err != nil {
			log.Fatalf("Error reading input file: %v", err)
		}

		privateKeyBytes, err := ioutil.ReadFile(privateKeyFile)
		if err != nil {
			log.Fatalf("Error reading private key file: %v", err)
		}

		privateKey, err := crypto.LoadKeypair(privateKeyFile)
		if err != nil {
			log.Fatalf("Error loading private key: %v", err)
		}

		signature, err := crypto.SignData(privateKey.PrivateKey, data)
		if err != nil {
			log.Fatalf("Error signing data: %v", err)
		}

		err = ioutil.WriteFile(signatureFile, signature, 0600)
		if err != nil {
			log.Fatalf("Error writing signature to file: %v", err)
		}

		fmt.Println("Data signed and signature saved successfully.")
	},
}

var verifySignatureCmd = &cobra.Command{
	Use:   "verifySignature",
	Short: "Verify data signature using ECDSA",
	Run: func(cmd *cobra.Command, args []string) {
		data, err := ioutil.ReadFile(inputFile)
		if err != nil {
			log.Fatalf("Error reading input file: %v", err)
		}

		publicKeyBytes, err := ioutil.ReadFile(publicKeyFile)
		if err != nil {
			log.Fatalf("Error reading public key file: %v", err)
		}

		publicKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(publicKeyBytes[:32]),
			Y:     new(big.Int).SetBytes(publicKeyBytes[32:]),
		}

		signature, err := ioutil.ReadFile(signatureFile)
		if err != nil {
			log.Fatalf("Error reading signature file: %v", err)
		}

		valid := crypto.VerifySignature(publicKey, data, signature)
		if !valid {
			fmt.Println("Signature verification failed.")
		} else {
			fmt.Println("Signature verified successfully.")
		}
	},
}

func main() {
	rootCmd.PersistentFlags().StringVar(&passphrase, "passphrase", "", "Passphrase for encryption/decryption")
	rootCmd.PersistentFlags().StringVar(&inputFile, "input", "", "Input file")
	rootCmd.PersistentFlags().StringVar(&outputFile, "output", "", "Output file")
	rootCmd.PersistentFlags().StringVar(&privateKeyFile, "privateKey", "", "Private key file")
	rootCmd.PersistentFlags().StringVar(&publicKeyFile, "publicKey", "", "Public key file")
	rootCmd.PersistentFlags().StringVar(&signatureFile, "signature", "", "Signature file")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
