package management

import (
	"errors"
	"sync"

	"github.com/synnergy_network/utils"
)

// WhitelistBlacklistManager manages whitelisting and blacklisting of addresses for SYN223 tokens.
type WhitelistBlacklistManager struct {
	mu          sync.RWMutex
	whitelist   map[string]bool
	blacklist   map[string]bool
}

// NewWhitelistBlacklistManager initializes a new WhitelistBlacklistManager instance.
func NewWhitelistBlacklistManager() *WhitelistBlacklistManager {
	return &WhitelistBlacklistManager{
		whitelist: make(map[string]bool),
		blacklist: make(map[string]bool),
	}
}

// AddToWhitelist adds an address to the whitelist.
func (wbm *WhitelistBlacklistManager) AddToWhitelist(address string) error {
	wbm.mu.Lock()
	defer wbm.mu.Unlock()

	if _, exists := wbm.whitelist[address]; exists {
		return errors.New("address already whitelisted")
	}

	wbm.whitelist[address] = true
	return nil
}

// RemoveFromWhitelist removes an address from the whitelist.
func (wbm *WhitelistBlacklistManager) RemoveFromWhitelist(address string) error {
	wbm.mu.Lock()
	defer wbm.mu.Unlock()

	if _, exists := wbm.whitelist[address]; !exists {
		return errors.New("address not found in whitelist")
	}

	delete(wbm.whitelist, address)
	return nil
}

// AddToBlacklist adds an address to the blacklist.
func (wbm *WhitelistBlacklistManager) AddToBlacklist(address string) error {
	wbm.mu.Lock()
	defer wbm.mu.Unlock()

	if _, exists := wbm.blacklist[address]; exists {
		return errors.New("address already blacklisted")
	}

	wbm.blacklist[address] = true
	return nil
}

// RemoveFromBlacklist removes an address from the blacklist.
func (wbm *WhitelistBlacklistManager) RemoveFromBlacklist(address string) error {
	wbm.mu.Lock()
	defer wbm.mu.Unlock()

	if _, exists := wbm.blacklist[address]; !exists {
		return errors.New("address not found in blacklist")
	}

	delete(wbm.blacklist, address)
	return nil
}

// IsWhitelisted checks if an address is in the whitelist.
func (wbm *WhitelistBlacklistManager) IsWhitelisted(address string) bool {
	wbm.mu.RLock()
	defer wbm.mu.RUnlock()

	return wbm.whitelist[address]
}

// IsBlacklisted checks if an address is in the blacklist.
func (wbm *WhitelistBlacklistManager) IsBlacklisted(address string) bool {
	wbm.mu.RLock()
	defer wbm.mu.RUnlock()

	return wbm.blacklist[address]
}

// ListWhitelisted returns all whitelisted addresses.
func (wbm *WhitelistBlacklistManager) ListWhitelisted() []string {
	wbm.mu.RLock()
	defer wbm.mu.RUnlock()

	var addresses []string
	for address := range wbm.whitelist {
		addresses = append(addresses, address)
	}

	return addresses
}

// ListBlacklisted returns all blacklisted addresses.
func (wbm *WhitelistBlacklistManager) ListBlacklisted() []string {
	wbm.mu.RLock()
	defer wbm.mu.RUnlock()

	var addresses []string
	for address := range wbm.blacklist {
		addresses = append(addresses, address)
	}

	return addresses
}

// EncryptWhitelist encrypts the whitelist using a specified encryption technique.
func (wbm *WhitelistBlacklistManager) EncryptWhitelist(passphrase string) (string, error) {
	wbm.mu.RLock()
	defer wbm.mu.RUnlock()

	// Serialize whitelist to JSON
	jsonData, err := utils.ToJSON(wbm.whitelist)
	if err != nil {
		return "", err
	}

	// Encrypt JSON data
	encryptedData, err := utils.EncryptData(jsonData, passphrase)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptWhitelist decrypts the whitelist using a specified decryption technique.
func (wbm *WhitelistBlacklistManager) DecryptWhitelist(encryptedData, passphrase string) error {
	wbm.mu.Lock()
	defer wbm.mu.Unlock()

	// Decrypt data
	decryptedData, err := utils.DecryptData(encryptedData, passphrase)
	if err != nil {
		return err
	}

	// Deserialize JSON data to whitelist
	var whitelist map[string]bool
	err = utils.FromJSON(decryptedData, &whitelist)
	if err != nil {
		return err
	}

	wbm.whitelist = whitelist
	return nil
}

// EncryptBlacklist encrypts the blacklist using a specified encryption technique.
func (wbm *WhitelistBlacklistManager) EncryptBlacklist(passphrase string) (string, error) {
	wbm.mu.RLock()
	defer wbm.mu.RUnlock()

	// Serialize blacklist to JSON
	jsonData, err := utils.ToJSON(wbm.blacklist)
	if err != nil {
		return "", err
	}

	// Encrypt JSON data
	encryptedData, err := utils.EncryptData(jsonData, passphrase)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptBlacklist decrypts the blacklist using a specified decryption technique.
func (wbm *WhitelistBlacklistManager) DecryptBlacklist(encryptedData, passphrase string) error {
	wbm.mu.Lock()
	defer wbm.mu.Unlock()

	// Decrypt data
	decryptedData, err := utils.DecryptData(encryptedData, passphrase)
	if err != nil {
		return err
	}

	// Deserialize JSON data to blacklist
	var blacklist map[string]bool
	err = utils.FromJSON(decryptedData, &blacklist)
	if err != nil {
		return err
	}

	wbm.blacklist = blacklist
	return nil
}
