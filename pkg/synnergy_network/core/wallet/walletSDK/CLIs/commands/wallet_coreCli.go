package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"your_project_path/pkg/synnergy_network/core/wallet"
	"your_project_path/utils/logger"
)

var rootCmd = &cobra.Command{
	Use:   "wallet",
	Short: "Synnergy Network Wallet CLI",
}

var coreCmd = &cobra.Command{
	Use:   "core",
	Short: "Manage Wallet Core Functions",
}

func init() {
	rootCmd.AddCommand(coreCmd)

	coreCmd.AddCommand(newHDWalletCmd)
	coreCmd.AddCommand(generateNewKeyPairCmd)
	coreCmd.AddCommand(getPublicKeyCmd)
	coreCmd.AddCommand(getAddressCmd)
	coreCmd.AddCommand(storeKeyCmd)
	coreCmd.AddCommand(restoreKeyCmd)
	coreCmd.AddCommand(newKeypairCmd)
	coreCmd.AddCommand(encryptPrivateKeyCmd)
	coreCmd.AddCommand(decryptPrivateKeyCmd)
	coreCmd.AddCommand(saveToDiskCmd)
	coreCmd.AddCommand(loadFromDiskCmd)
	coreCmd.AddCommand(signDataCmd)
	coreCmd.AddCommand(verifySignatureCmd)
	coreCmd.AddCommand(addCurrencyCmd)
	coreCmd.AddCommand(getBalanceCmd)
	coreCmd.AddCommand(updateBalanceCmd)
	coreCmd.AddCommand(transactionHistoryCmd)
	coreCmd.AddCommand(saveMultiCurrencyWalletCmd)
	coreCmd.AddCommand(loadMultiCurrencyWalletCmd)
	coreCmd.AddCommand(notifyBalanceUpdateCmd)
	coreCmd.AddCommand(notifyTransactionCmd)
	coreCmd.AddCommand(freezeWalletCmd)
	coreCmd.AddCommand(unfreezeWalletCmd)
	coreCmd.AddCommand(sendTransactionCmd)
	coreCmd.AddCommand(encryptMetadataCmd)
	coreCmd.AddCommand(saveMetadataCmd)
	coreCmd.AddCommand(loadMetadataCmd)
	coreCmd.AddCommand(signTransactionCmd)
	coreCmd.AddCommand(publishTransactionCmd)
	coreCmd.AddCommand(recoverWalletFromMnemonicCmd)
	coreCmd.AddCommand(getWalletAddressCmd)
}

var newHDWalletCmd = &cobra.Command{
	Use:   "new-hd-wallet [seed]",
	Short: "Create a new HD Wallet with a given seed",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		seed := []byte(args[0])
		hdWallet, err := wallet.NewHDWallet(seed)
		if err != nil {
			fmt.Println("Error creating HD Wallet:", err)
			return
		}
		fmt.Println("HD Wallet created successfully with master key:", hdWallet.MasterKey)
	},
}

var generateNewKeyPairCmd = &cobra.Command{
	Use:   "generate-keypair [path]",
	Short: "Generate a new key pair from the HD Wallet at the given path",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]
		hdWallet, err := wallet.NewHDWallet([]byte("seed")) // Replace with actual seed handling
		if err != nil {
			fmt.Println("Error creating HD Wallet:", err)
			return
		}
		privKey, err := hdWallet.GenerateNewKeyPair(path)
		if err != nil {
			fmt.Println("Error generating new key pair:", err)
			return
		}
		fmt.Println("New key pair generated successfully:", privKey)
	},
}

var getPublicKeyCmd = &cobra.Command{
	Use:   "get-public-key [privKey]",
	Short: "Get the public key for a given private key",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		privKeyBytes, err := hex.DecodeString(args[0])
		if err != nil {
			fmt.Println("Invalid private key:", err)
			return
		}

		privKey, err := x509.ParseECPrivateKey(privKeyBytes)
		if err != nil {
			fmt.Println("Error parsing private key:", err)
			return
		}

		pubKey := privKey.PublicKey
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
		if err != nil {
			fmt.Println("Error marshalling public key:", err)
			return
		}

		fmt.Println("Public key:", hex.EncodeToString(pubKeyBytes))
	},
}

var getAddressCmd = &cobra.Command{
	Use:   "get-address [pubKey]",
	Short: "Generate a public address for a given public key",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pubKeyBytes, err := hex.DecodeString(args[0])
		if err != nil {
			fmt.Println("Invalid public key:", err)
			return
		}

		pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			fmt.Println("Error parsing public key:", err)
			return
		}

		address := wallet.Address(pubKey.(*ecdsa.PublicKey))
		fmt.Println("Address:", address)
	},
}

var storeKeyCmd = &cobra.Command{
	Use:   "store-key [privKey] [passphrase]",
	Short: "Store the private key securely",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		privKeyBytes, err := hex.DecodeString(args[0])
		if err != nil {
			fmt.Println("Invalid private key:", err)
			return
		}

		privKey, err := x509.ParseECPrivateKey(privKeyBytes)
		if err != nil {
			fmt.Println("Error parsing private key:", err)
			return
		}

		passphrase := args[1]
		err = wallet.StoreKey(privKey, passphrase)
		if err != nil {
			fmt.Println("Error storing key:", err)
			return
		}

		fmt.Println("Key stored successfully.")
	},
}

var restoreKeyCmd = &cobra.Command{
	Use:   "restore-key [passphrase]",
	Short: "Restore the private key from secure storage",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		passphrase := args[0]
		privKey, err := wallet.RestoreKey(passphrase)
		if err != nil {
			fmt.Println("Error restoring key:", err)
			return
		}

		privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
		if err != nil {
			fmt.Println("Error marshalling private key:", err)
			return
		}

		fmt.Println("Private key:", hex.EncodeToString(privKeyBytes))
	},
}

var newKeypairCmd = &cobra.Command{
	Use:   "new-keypair",
	Short: "Generate a new ECDSA keypair",
	Run: func(cmd *cobra.Command, args []string) {
		keypair, err := wallet.NewKeypair()
		if err != nil {
			fmt.Println("Error generating new keypair:", err)
			return
		}

		privKeyBytes, err := x509.MarshalECPrivateKey(keypair.PrivateKey)
		if err != nil {
			fmt.Println("Error marshalling private key:", err)
			return
		}

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(keypair.PublicKey)
		if err != nil {
			fmt.Println("Error marshalling public key:", err)
			return
		}

		fmt.Println("New keypair generated successfully:")
		fmt.Println("Private key:", hex.EncodeToString(privKeyBytes))
		fmt.Println("Public key:", hex.EncodeToString(pubKeyBytes))
	},
}

var encryptPrivateKeyCmd = &cobra.Command{
	Use:   "encrypt-private-key [privKey] [passphrase]",
	Short: "Encrypt the private key with a passphrase",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		privKeyBytes, err := hex.DecodeString(args[0])
		if err != nil {
			fmt.Println("Invalid private key:", err)
			return
		}

		privKey, err := x509.ParseECPrivateKey(privKeyBytes)
		if err != nil {
			fmt.Println("Error parsing private key:", err)
			return
		}

		passphrase := args[1]
		encryptedKey, err := wallet.EncryptPrivateKey(privKey, passphrase)
		if err != nil {
			fmt.Println("Error encrypting private key:", err)
			return
		}

		fmt.Println("Encrypted private key:", hex.EncodeToString(encryptedKey))
	},
}

var decryptPrivateKeyCmd = &cobra.Command{
	Use:   "decrypt-private-key [encryptedData] [passphrase]",
	Short: "Decrypt the private key with a passphrase",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		encryptedData, err := hex.DecodeString(args[0])
		if err != nil {
			fmt.Println("Invalid encrypted data:", err)
			return
		}

		passphrase := args[1]
		privKey, err := wallet.DecryptPrivateKey(encryptedData, passphrase)
		if err != nil {
			fmt.Println("Error decrypting private key:", err)
			return
		}

		privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
		if err != nil {
			fmt.Println("Error marshalling private key:", err)
			return
		}

		fmt.Println("Decrypted private key:", hex.EncodeToString(privKeyBytes))
	},
}

var saveToDiskCmd = &cobra.Command{
	Use:   "save-to-disk [filename] [passphrase]",
	Short: "Save the encrypted private key to a file",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		filename := args[0]
		passphrase := args[1]

		keypair, err := wallet.NewKeypair()
		if err != nil {
			fmt.Println("Error generating new keypair:", err)
			return
		}

		err = keypair.SaveToDisk(filename, passphrase)
		if err != nil {
			fmt.Println("Error saving key to disk:", err)
			return
		}

		fmt.Println("Key saved to disk successfully.")
	},
}

var loadFromDiskCmd = &cobra.Command{
	Use:   "load-from-disk [filename] [passphrase]",
	Short: "Load the encrypted private key from a file and decrypt it",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		filename := args[0]
		passphrase := args[1]

		privKey, err := wallet.LoadFromDisk(filename, passphrase)
		if err != nil {
			fmt.Println("Error loading key from disk:", err)
			return
		}

		privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
		if err != nil {
			fmt.Println("Error marshalling private key:", err)
			return
		}

		fmt.Println("Loaded and decrypted private key:", hex.EncodeToString(privKeyBytes))
	},
}

var signDataCmd = &cobra.Command{
	Use:   "sign-data [data]",
	Short: "Sign the given data using the private key",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		data := []byte(args[0])
		keypair, err := wallet.NewKeypair()
		if err != nil {
			fmt.Println("Error generating new keypair:", err)
			return
		}

		signature, err := keypair.SignData(data)
		if err != nil {
			fmt.Println("Error signing data:", err)
			return
		}

		fmt.Println("Signature:", hex.EncodeToString(signature))
	},
}

var verifySignatureCmd = &cobra.Command{
	Use:   "verify-signature [data] [signature]",
	Short: "Verify the data against the signature and public key",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		data := []byte(args[0])
		signature, err := hex.DecodeString(args[1])
		if err != nil {
			fmt.Println("Invalid signature:", err)
			return
		}

		keypair, err := wallet.NewKeypair()
		if err != nil {
			fmt.Println("Error generating new keypair:", err)
			return
		}

		isValid := wallet.VerifySignature(keypair.PublicKey, data, signature)
		if isValid {
			fmt.Println("Signature is valid.")
		} else {
			fmt.Println("Signature is invalid.")
		}
	},
}

var addCurrencyCmd = &cobra.Command{
	Use:   "add-currency [name] [blockchain]",
	Short: "Add support for a new currency within the wallet",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		blockchain := args[1]
		keyPair, err := wallet.NewKeypair()
		if err != nil {
			fmt.Println("Error generating new keypair:", err)
			return
		}

		multiCurrencyWallet := wallet.NewMultiCurrencyWallet()
		err = multiCurrencyWallet.AddCurrency(name, blockchain, keyPair)
		if err != nil {
			fmt.Println("Error adding currency:", err)
			return
		}

		fmt.Println("Currency added successfully.")
	},
}

var getBalanceCmd = &cobra.Command{
	Use:   "get-balance [currency]",
	Short: "Retrieve the balance for a specific currency",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		currency := args[0]
		multiCurrencyWallet := wallet.NewMultiCurrencyWallet()
		balance, err := multiCurrencyWallet.GetBalance(currency)
		if err != nil {
			fmt.Println("Error retrieving balance:", err)
			return
		}

		fmt.Println("Balance:", balance)
	},
}

var updateBalanceCmd = &cobra.Command{
	Use:   "update-balance [currency] [amount]",
	Short: "Update the balance for a given currency",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		currency := args[0]
		amount, err := strconv.ParseFloat(args[1], 64)
		if err != nil {
			fmt.Println("Invalid amount:", err)
			return
		}

		multiCurrencyWallet := wallet.NewMultiCurrencyWallet()
		err = multiCurrencyWallet.UpdateBalance(currency, amount)
		if err != nil {
			fmt.Println("Error updating balance:", err)
			return
		}

		fmt.Println("Balance updated successfully.")
	},
}

var transactionHistoryCmd = &cobra.Command{
	Use:   "transaction-history [currency] [transactionID]",
	Short: "Add a transaction ID to the currency account",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		currency := args[0]
		transactionID := args[1]

		multiCurrencyWallet := wallet.NewMultiCurrencyWallet()
		err := multiCurrencyWallet.TransactionHistory(currency, transactionID)
		if err != nil {
			fmt.Println("Error adding transaction ID:", err)
			return
		}

		fmt.Println("Transaction ID added successfully.")
	},
}

var saveMultiCurrencyWalletCmd = &cobra.Command{
	Use:   "save-multi-currency-wallet",
	Short: "Save the state of the multi-currency wallet to storage",
	Run: func(cmd *cobra.Command, args []string) {
		multiCurrencyWallet := wallet.NewMultiCurrencyWallet()
		err := multiCurrencyWallet.Save()
		if err != nil {
			fmt.Println("Error saving multi-currency wallet:", err)
			return
		}

		fmt.Println("Multi-currency wallet saved successfully.")
	},
}

var loadMultiCurrencyWalletCmd = &cobra.Command{
	Use:   "load-multi-currency-wallet",
	Short: "Load the state of the multi-currency wallet from storage",
	Run: func(cmd *cobra.Command, args []string) {
		multiCurrencyWallet := wallet.NewMultiCurrencyWallet()
		err := multiCurrencyWallet.Load()
		if err != nil {
			fmt.Println("Error loading multi-currency wallet:", err)
			return
		}

		fmt.Println("Multi-currency wallet loaded successfully.")
	},
}

var notifyBalanceUpdateCmd = &cobra.Command{
	Use:   "notify-balance-update [currency] [amount]",
	Short: "Send a balance update notification to all clients",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		currency := args[0]
		amount, err := strconv.ParseFloat(args[1], 64)
		if err != nil {
			fmt.Println("Invalid amount:", err)
			return
		}

		notificationService := wallet.NewNotificationService([]byte("encryption-key")) // Replace with actual encryption key
		notificationService.NotifyBalanceUpdate(currency, amount)
		fmt.Println("Balance update notification sent.")
	},
}

var notifyTransactionCmd = &cobra.Command{
	Use:   "notify-transaction [currency] [amount]",
	Short: "Send a transaction notification to all clients",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		currency := args[0]
		amount, err := strconv.ParseFloat(args[1], 64)
		if err != nil {
			fmt.Println("Invalid amount:", err)
			return
		}

		notificationService := wallet.NewNotificationService([]byte("encryption-key")) // Replace with actual encryption key
		notificationService.NotifyTransaction(currency, amount)
		fmt.Println("Transaction notification sent.")
	},
}

var freezeWalletCmd = &cobra.Command{
	Use:   "freeze-wallet",
	Short: "Freeze the wallet, blocking all outgoing transactions",
	Run: func(cmd *cobra.Command, args []string) {
		walletService := core.NewWalletService(storage.NewWalletStorage())
		err := walletService.LoadWallet()
		if err != nil {
			fmt.Println("Error loading wallet:", err)
			return
		}

		wallet := wallet.NewWallet(walletService)
		err = wallet.Freeze()
		if err != nil {
			fmt.Println("Error freezing wallet:", err)
			return
		}

		fmt.Println("Wallet has been successfully frozen.")
	},
}

var unfreezeWalletCmd = &cobra.Command{
	Use:   "unfreeze-wallet",
	Short: "Unfreeze the wallet, allowing transactions",
	Run: func(cmd *cobra.Command, args []string) {
		walletService := core.NewWalletService(storage.NewWalletStorage())
		err := walletService.LoadWallet()
		if err != nil {
			fmt.Println("Error loading wallet:", err)
			return
		}

		wallet := wallet.NewWallet(walletService)
		err = wallet.Unfreeze()
		if err != nil {
			fmt.Println("Error unfreezing wallet:", err)
			return
		}

		fmt.Println("Wallet has been successfully unfrozen.")
	},
}

var sendTransactionCmd = &cobra.Command{
	Use:   "send-transaction [to] [amount]",
	Short: "Initiate a new transaction from the wallet",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		to := args[0]
		amount, err := strconv.ParseFloat(args[1], 64)
		if err != nil {
			fmt.Println("Invalid amount:", err)
			return
		}

		walletService := core.NewWalletService(storage.NewWalletStorage())
		err = walletService.LoadWallet()
		if err != nil {
			fmt.Println("Error loading wallet:", err)
			return
		}

		wallet := wallet.NewWallet(walletService)
		err = wallet.SendTransaction(to, amount)
		if err != nil {
			fmt.Println("Error sending transaction:", err)
			return
		}

		fmt.Println("Transaction sent successfully.")
	},
}

var encryptMetadataCmd = &cobra.Command{
	Use:   "encrypt-metadata [key]",
	Short: "Encrypt wallet metadata with a key",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := []byte(args[0])
		metadata, err := wallet.NewWalletMetadata("ownerID") // Replace "ownerID" with actual owner ID
		if err != nil {
			fmt.Println("Error creating wallet metadata:", err)
			return
		}

		encryptedMetadata, err := metadata.EncryptMetadata(key)
		if err != nil {
			fmt.Println("Error encrypting metadata:", err)
			return
		}

		fmt.Println("Encrypted Metadata:", encryptedMetadata)
	},
}

var saveMetadataCmd = &cobra.Command{
	Use:   "save-metadata [filePath] [key]",
	Short: "Save encrypted wallet metadata to a file",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		key := []byte(args[1])

		metadata, err := wallet.NewWalletMetadata("ownerID") // Replace "ownerID" with actual owner ID
		if err != nil {
			fmt.Println("Error creating wallet metadata:", err)
			return
		}

		err = metadata.SaveMetadata(filePath, key)
		if err != nil {
			fmt.Println("Error saving metadata:", err)
			return
		}

		fmt.Println("Metadata saved successfully.")
	},
}

var loadMetadataCmd = &cobra.Command{
	Use:   "load-metadata [filePath] [key]",
	Short: "Load metadata from a file, decrypting it if necessary",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		key := []byte(args[1])

		metadata, err := wallet.LoadMetadata(filePath, key)
		if err != nil {
			fmt.Println("Error loading metadata:", err)
			return
		}

		fmt.Println("Loaded Metadata:", metadata)
	},
}

var signTransactionCmd = &cobra.Command{
	Use:   "sign-transaction [transaction]",
	Short: "Sign a transaction with the loaded private key",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		tx := args[0] // This should be properly deserialized into a Transaction object

		walletService := core.NewWalletService(storage.NewWalletStorage())
		err := walletService.LoadWallet()
		if err != nil {
			fmt.Println("Error loading wallet:", err)
			return
		}

		signature, err := walletService.SignTransaction(tx)
		if err != nil {
			fmt.Println("Error signing transaction:", err)
			return
		}

		fmt.Println("Transaction signed successfully. Signature:", signature)
	},
}

var publishTransactionCmd = &cobra.Command{
	Use:   "publish-transaction [transaction]",
	Short: "Broadcast the signed transaction to the network",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		tx := args[0] // This should be properly deserialized into a Transaction object

		walletService := core.NewWalletService(storage.NewWalletStorage())
		err := walletService.PublishTransaction(tx)
		if err != nil {
			fmt.Println("Error publishing transaction:", err)
			return
		}

		fmt.Println("Transaction published successfully.")
	},
}

var recoverWalletFromMnemonicCmd = &cobra.Command{
	Use:   "recover-wallet [mnemonic] [passphrase]",
	Short: "Recover wallet from mnemonic and passphrase",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		mnemonic := args[0]
		passphrase := args[1]

		walletService := core.NewWalletService(storage.NewWalletStorage())
		err := walletService.RecoverWalletFromMnemonic(mnemonic, passphrase)
		if err != nil {
			fmt.Println("Error recovering wallet:", err)
			return
		}

		fmt.Println("Wallet recovered successfully.")
	},
}

var getWalletAddressCmd = &cobra.Command{
	Use:   "get-wallet-address",
	Short: "Generate wallet address from public key",
	Run: func(cmd *cobra.Command, args []string) {
		walletService := core.NewWalletService(storage.NewWalletStorage())
		err := walletService.LoadWallet()
		if err != nil {
			fmt.Println("Error loading wallet:", err)
			return
		}

		address := walletService.GetWalletAddress()
		fmt.Println("Wallet Address:", address)
	},
}


func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
