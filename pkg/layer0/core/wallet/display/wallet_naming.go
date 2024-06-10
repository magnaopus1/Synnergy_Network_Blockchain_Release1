package display

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
)

// WalletNaming manages the naming and aliasing of wallets.
type WalletNaming struct {
	names   map[string]string
	file    string
	mutex   sync.RWMutex
}

// NewWalletNaming creates a new WalletNaming instance.
func NewWalletNaming(file string) *WalletNaming {
	wn := &WalletNaming{
		names: make(map[string]string),
		file:  file,
	}
	wn.loadNames()
	return wn
}

// loadNames loads wallet names from a file.
func (wn *WalletNaming) loadNames() error {
	wn.mutex.Lock()
	defer wn.mutex.Unlock()

	if _, err := os.Stat(wn.file); os.IsNotExist(err) {
		return nil // No file to load, assume empty names
	}

	data, err := ioutil.ReadFile(wn.file)
	if err != nil {
		return fmt.Errorf("failed to read names file: %v", err)
	}

	err = json.Unmarshal(data, &wn.names)
	if err != nil {
		return fmt.Errorf("failed to unmarshal names data: %v", err)
	}

	return nil
}

// saveNames saves wallet names to a file.
func (wn *WalletNaming) saveNames() error {
	wn.mutex.RLock()
	defer wn.mutex.RUnlock()

	data, err := json.MarshalIndent(wn.names, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal names data: %v", err)
	}

	err = ioutil.WriteFile(wn.file, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write names file: %v", err)
	}

	return nil
}

// SetName assigns a human-readable name to a wallet address.
func (wn *WalletNaming) SetName(address, name string) error {
	if address == "" || name == "" {
		return errors.New("address and name cannot be empty")
	}

	wn.mutex.Lock()
	defer wn.mutex.Unlock()

	wn.names[address] = name
	return wn.saveNames()
}

// GetName retrieves the human-readable name for a wallet address.
func (wn *WalletNaming) GetName(address string) (string, error) {
	wn.mutex.RLock()
	defer wn.mutex.RUnlock()

	name, exists := wn.names[address]
	if !exists {
		return "", errors.New("name not found for the given address")
	}

	return name, nil
}

// RemoveName removes the human-readable name for a wallet address.
func (wn *WalletNaming) RemoveName(address string) error {
	wn.mutex.Lock()
	defer wn.mutex.Unlock()

	if _, exists := wn.names[address]; !exists {
		return errors.New("name not found for the given address")
	}

	delete(wn.names, address)
	return wn.saveNames()
}

// ListNames returns all wallet addresses and their assigned names.
func (wn *WalletNaming) ListNames() map[string]string {
	wn.mutex.RLock()
	defer wn.mutex.RUnlock()

	// Return a copy to avoid external modification
	namesCopy := make(map[string]string)
	for k, v := range wn.names {
		namesCopy[k] = v
	}
	return namesCopy
}

// ImportNames imports wallet names from an external file.
func (wn *WalletNaming) ImportNames(file string) error {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read import file: %v", err)
	}

	var importedNames map[string]string
	err = json.Unmarshal(data, &importedNames)
	if err != nil {
		return fmt.Errorf("failed to unmarshal import data: %v", err)
	}

	wn.mutex.Lock()
	defer wn.mutex.Unlock()

	for address, name := range importedNames {
		wn.names[address] = name
	}

	return wn.saveNames()
}

// ExportNames exports wallet names to an external file.
func (wn *WalletNaming) ExportNames(file string) error {
	wn.mutex.RLock()
	defer wn.mutex.RUnlock()

	data, err := json.MarshalIndent(wn.names, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal export data: %v", err)
	}

	err = ioutil.WriteFile(file, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write export file: %v", err)
	}

	return nil
}

// ClearNames clears all wallet names.
func (wn *WalletNaming) ClearNames() error {
	wn.mutex.Lock()
	defer wn.mutex.Unlock()

	wn.names = make(map[string]string)
	return wn.saveNames()
}

func main() {
	// Example usage
	walletNaming := NewWalletNaming("wallet_names.json")
	err := walletNaming.SetName("0x1234", "Primary Wallet")
	if err != nil {
		fmt.Println("Error setting name:", err)
		return
	}

	name, err := walletNaming.GetName("0x1234")
	if err != nil {
		fmt.Println("Error getting name:", err)
		return
	}
	fmt.Println("Wallet name:", name)

	err = walletNaming.RemoveName("0x1234")
	if err != nil {
		fmt.Println("Error removing name:", err)
		return
	}

	names := walletNaming.ListNames()
	fmt.Println("All names:", names)
}
