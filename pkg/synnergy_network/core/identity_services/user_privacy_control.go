package user_privacy_control

import (
	"crypto/rand"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"sync"

	"golang.org/x/crypto/scrypt"
)

// NewAutomatedConsentEnforcement initializes a new AutomatedConsentEnforcement instance
func NewAutomatedConsentEnforcement() *AutomatedConsentEnforcement {
	return &AutomatedConsentEnforcement{
		Consents: make(map[string]*UserConsent),
	}
}

// DefineUserConsent defines consent preferences for a user
func (ace *AutomatedConsentEnforcement) DefineUserConsent(userID string, dataTypes map[string]ConsentDetails, passphrase string) (*UserConsent, error) {
	ace.Mutex.Lock()
	defer ace.Mutex.Unlock()

	consent := &UserConsent{
		UserID:    userID,
		DataTypes: dataTypes,
	}

	// Encrypt the consent details
	encryptedConsent, consentHash, err := encryptConsent(consent, passphrase)
	if err != nil {
		return nil, err
	}

	consent.ConsentHash = consentHash

	ace.Consents[userID] = consent
	return consent, nil
}

// encryptConsent encrypts the consent details using AES encryption
func encryptConsent(consent *UserConsent, passphrase string) (string, string, error) {
	plaintext, err := json.Marshal(consent)
	if err != nil {
		return "", "", err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", "", err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ciphertext), hex.EncodeToString(dk), nil
}

// decryptConsent decrypts the consent details using AES decryption
func decryptConsent(encryptedConsent, passphrase, consentHash string) (*UserConsent, error) {
	data, err := hex.DecodeString(encryptedConsent)
	if err != nil {
		return nil, err
	}

	salt := data[:16]
	ciphertext := data[16:]

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	if hex.EncodeToString(dk) != consentHash {
		return nil, errors.New("incorrect passphrase")
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var consent UserConsent
	if err := json.Unmarshal(plaintext, &consent); err != nil {
		return nil, err
	}

	return &consent, nil
}

// CheckConsent checks if a user has consented to a specific action on a data type
func (ace *AutomatedConsentEnforcement) CheckConsent(userID, dataType, action string) (bool, error) {
	ace.Mutex.Lock()
	defer ace.Mutex.Unlock()

	consent, exists := ace.Consents[userID]
	if !exists {
		return false, errors.New("user consent not found")
	}

	details, exists := consent.DataTypes[dataType]
	if !exists {
		return false, errors.New("data type consent not found")
	}

	for _, allowedAction := range details.AllowedActions {
		if allowedAction == action {
			return true, nil
		}
	}

	return false, nil
}

// RevokeConsent revokes consent for a user
func (ace *AutomatedConsentEnforcement) RevokeConsent(userID string) error {
	ace.Mutex.Lock()
	defer ace.Mutex.Unlock()

	if _, exists := ace.Consents[userID]; !exists {
		return errors.New("user consent not found")
	}

	delete(ace.Consents, userID)
	return nil
}


// NewConsentLedger initializes a new ConsentLedger.
func NewConsentLedger() *ConsentLedger {
	return &ConsentLedger{
		Records: make(map[string]*ConsentRecord),
	}
}

// GrantConsent records a new user consent.
func (cl *ConsentLedger) GrantConsent(userID, dataType, purpose, passphrase string, expirationDate time.Time) (*ConsentRecord, error) {
	cl.Mutex.Lock()
	defer cl.Mutex.Unlock()

	consent := &ConsentRecord{
		UserID:         userID,
		DataType:       dataType,
		Granted:        true,
		Purpose:        purpose,
		ExpirationDate: expirationDate,
		Timestamp:      time.Now(),
	}

	encryptedConsent, consentHash, err := encryptConsent(consent, passphrase)
	if err != nil {
		return nil, err
	}

	consent.ConsentHash = consentHash

	cl.Records[userID+"_"+dataType] = consent

	// Store the encrypted consent on the blockchain (pseudo-code)
	// StoreOnBlockchain(encryptedConsent)

	return consent, nil
}

// RevokeConsent revokes an existing user consent.
func (cl *ConsentLedger) RevokeConsent(userID, dataType, passphrase string) error {
	cl.Mutex.Lock()
	defer cl.Mutex.Unlock()

	recordKey := userID + "_" + dataType
	consent, exists := cl.Records[recordKey]
	if !exists {
		return errors.New("consent record not found")
	}

	consent.Granted = false
	consent.Timestamp = time.Now()

	encryptedConsent, consentHash, err := encryptConsent(consent, passphrase)
	if err != nil {
		return err
	}

	consent.ConsentHash = consentHash

	cl.Records[recordKey] = consent

	// Update the encrypted consent on the blockchain (pseudo-code)
	// UpdateOnBlockchain(encryptedConsent)

	return nil
}

// GetConsent retrieves a user consent record.
func (cl *ConsentLedger) GetConsent(userID, dataType, passphrase string) (*ConsentRecord, error) {
	cl.Mutex.Lock()
	defer cl.Mutex.Unlock()

	recordKey := userID + "_" + dataType
	consent, exists := cl.Records[recordKey]
	if !exists {
		return nil, errors.New("consent record not found")
	}

	decryptedConsent, err := decryptConsent(consent.ConsentHash, passphrase, consent.ConsentHash)
	if err != nil {
		return nil, err
	}

	return decryptedConsent, nil
}

// encryptConsent encrypts a consent record using AES encryption.
func encryptConsent(consent *ConsentRecord, passphrase string) (string, string, error) {
	plaintext, err := json.Marshal(consent)
	if err != nil {
		return "", "", err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", "", err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ciphertext), hex.EncodeToString(dk), nil
}

// decryptConsent decrypts a consent record using AES decryption.
func decryptConsent(encryptedConsent, passphrase, keyHash string) (*ConsentRecord, error) {
	data, err := hex.DecodeString(encryptedConsent)
	if err != nil {
		return nil, err
	}

	salt := data[:16]
	ciphertext := data[16:]

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	if hex.EncodeToString(dk) != keyHash {
		return nil, errors.New("incorrect passphrase")
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var consent ConsentRecord
	if err := json.Unmarshal(plaintext, &consent); err != nil {
		return nil, err
	}

	return &consent, nil
}

// NewConsentManager creates a new instance of ConsentManager.
func NewConsentManager() *ConsentManager {
	return &ConsentManager{}
}

// RecordConsent captures and records user consent in the blockchain.
func (cm *ConsentManager) RecordConsent(userID, dataCategory, purpose, duration string) (string, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	consent := ConsentDetail{
		ConsentID:       uuid.NewString(),
		UserID:          userID,
		DataCategory:    dataCategory,
		Purpose:         purpose,
		ConsentDuration: duration,
		ConsentActive:   true,
	}

	data, err := json.Marshal(consent)
	if err != nil {
		return "", err
	}

	// Simulate storing consent in the blockchain.
	if err := blockchain.StoreData(consent.ConsentID, data); err != nil {
		return "", err
	}

	return consent.ConsentID, nil
}

// UpdateConsent allows users to update their existing consent preferences.
func (cm *ConsentManager) UpdateConsent(consentID string, active bool) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	data, err := blockchain.RetrieveData(consentID)
	if err != nil {
		return err
	}

	var consent ConsentDetail
	if err := json.Unmarshal(data, &consent); err != nil {
		return err
	}

	consent.ConsentActive = active

	updatedData, err := json.Marshal(consent)
	if err != nil {
		return err
	}

	// Update the consent data on the blockchain.
	return blockchain.UpdateData(consent.ConsentID, updatedData)
}

// VerifyConsent checks the active status of consent for a given ID.
func (cm *ConsentManager) VerifyConsent(consentID string) (bool, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	data, err := blockchain.RetrieveData(consentID)
	if err != nil {
		return false, err
	}

	var consent ConsentDetail
	if err := json.Unmarshal(data, &consent); err != nil {
		return false, err
	}

	return consent.ConsentActive, nil
}

// NewDataMaskingManager initializes a new DataMaskingManager
func NewDataMaskingManager(passphrase string) (*DataMaskingManager, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	secretKey, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return &DataMaskingManager{
		KeyManager: &KeyManager{
			Salt:      salt,
			SecretKey: secretKey,
		},
	}, nil
}

// EncryptData encrypts the given data using AES encryption
func (dmm *DataMaskingManager) EncryptData(plaintext string) (string, error) {
	block, err := aes.NewCipher(dmm.KeyManager.SecretKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the given data using AES encryption
func (dmm *DataMaskingManager) DecryptData(encryptedText string) (string, error) {
	ciphertext, err := hex.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dmm.KeyManager.SecretKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// MaskSensitiveData applies data masking techniques to protect sensitive data
func (dmm *DataMaskingManager) MaskSensitiveData(data string) (string, error) {
	// Simple example: replace sensitive parts with asterisks
	// Customize this function based on the specific data masking requirements
	maskedData := data[:2] + "****" + data[len(data)-2:]
	return maskedData, nil
}

// NewDynamicConsentManager initializes a new DynamicConsentManager instance
func NewDynamicConsentManager() *DynamicConsentManager {
	return &DynamicConsentManager{
		Consents: make(map[string]*UserConsent),
	}
}

// DefineUserConsent defines consent preferences for a user
func (dcm *DynamicConsentManager) DefineUserConsent(userID string, dataTypes map[string]ConsentDetails, passphrase string) (*UserConsent, error) {
	dcm.Mutex.Lock()
	defer dcm.Mutex.Unlock()

	consent := &UserConsent{
		UserID:    userID,
		DataTypes: dataTypes,
		UpdatedAt: time.Now(),
	}

	// Encrypt the consent details
	encryptedConsent, consentHash, err := encryptConsent(consent, passphrase)
	if err != nil {
		return nil, err
	}

	consent.ConsentHash = consentHash

	dcm.Consents[userID] = consent
	return consent, nil
}

// encryptConsent encrypts the consent details using AES encryption
func encryptConsent(consent *UserConsent, passphrase string) (string, string, error) {
	plaintext, err := json.Marshal(consent)
	if err != nil {
		return "", "", err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", "", err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ciphertext), hex.EncodeToString(dk), nil
}

// decryptConsent decrypts the consent details using AES decryption
func decryptConsent(encryptedConsent, passphrase, consentHash string) (*UserConsent, error) {
	data, err := hex.DecodeString(encryptedConsent)
	if err != nil {
		return nil, err
	}

	salt := data[:16]
	ciphertext := data[16:]

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	if hex.EncodeToString(dk) != consentHash {
		return nil, errors.New("incorrect passphrase")
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var consent UserConsent
	if err := json.Unmarshal(plaintext, &consent); err != nil {
		return nil, err
	}

	return &consent, nil
}

// CheckConsent checks if a user has consented to a specific action on a data type
func (dcm *DynamicConsentManager) CheckConsent(userID, dataType, action string) (bool, error) {
	dcm.Mutex.Lock()
	defer dcm.Mutex.Unlock()

	consent, exists := dcm.Consents[userID]
	if !exists {
		return false, errors.New("user consent not found")
	}

	details, exists := consent.DataTypes[dataType]
	if !exists {
		return false, errors.New("data type consent not found")
	}

	for _, allowedAction := range details.AllowedActions {
		if allowedAction == action {
			return true, nil
		}
	}

	return false, nil
}

// RevokeConsent revokes consent for a user
func (dcm *DynamicConsentManager) RevokeConsent(userID string) error {
	dcm.Mutex.Lock()
	defer dcm.Mutex.Unlock()

	if _, exists := dcm.Consents[userID]; !exists {
		return errors.New("user consent not found")
	}

	delete(dcm.Consents, userID)
	return nil
}

// UpdateUserConsent updates the consent preferences for a user
func (dcm *DynamicConsentManager) UpdateUserConsent(userID string, dataTypes map[string]ConsentDetails, passphrase string) (*UserConsent, error) {
	dcm.Mutex.Lock()
	defer dcm.Mutex.Unlock()

	consent, exists := dcm.Consents[userID]
	if !exists {
		return nil, errors.New("user consent not found")
	}

	consent.DataTypes = dataTypes
	consent.UpdatedAt = time.Now()

	encryptedConsent, consentHash, err := encryptConsent(consent, passphrase)
	if err != nil {
		return nil, err
	}

	consent.ConsentHash = consentHash

	dcm.Consents[userID] = consent
	return consent, nil
}


// NewGranularConsentManager initializes a new GranularConsentManager
func NewGranularConsentManager() *GranularConsentManager {
	return &GranularConsentManager{
		Consents: make(map[string]*UserConsent),
	}
}

// DefineUserConsent defines consent preferences for a user
func (gcm *GranularConsentManager) DefineUserConsent(userID string, dataTypes map[string]ConsentDetails, passphrase string) (*UserConsent, error) {
	gcm.Mutex.Lock()
	defer gcm.Mutex.Unlock()

	consent := &UserConsent{
		UserID:    userID,
		DataTypes: dataTypes,
		UpdatedAt: time.Now(),
	}

	// Encrypt the consent details
	encryptedConsent, consentHash, err := encryptConsent(consent, passphrase)
	if err != nil {
		return nil, err
	}

	consent.ConsentHash = consentHash

	gcm.Consents[userID] = consent
	return consent, nil
}

// encryptConsent encrypts the consent details using AES encryption
func encryptConsent(consent *UserConsent, passphrase string) (string, string, error) {
	plaintext, err := json.Marshal(consent)
	if err != nil {
		return "", "", err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", "", err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ciphertext), hex.EncodeToString(dk), nil
}

// decryptConsent decrypts the consent details using AES decryption
func decryptConsent(encryptedConsent, passphrase, consentHash string) (*UserConsent, error) {
	data, err := hex.DecodeString(encryptedConsent)
	if err != nil {
		return nil, err
	}

	salt := data[:16]
	ciphertext := data[16:]

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	if hex.EncodeToString(dk) != consentHash {
		return nil, errors.New("incorrect passphrase")
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var consent UserConsent
	if err := json.Unmarshal(plaintext, &consent); err != nil {
		return nil, err
	}

	return &consent, nil
}

// CheckConsent checks if a user has consented to a specific action on a data type
func (gcm *GranularConsentManager) CheckConsent(userID, dataType, action string) (bool, error) {
	gcm.Mutex.Lock()
	defer gcm.Mutex.Unlock()

	consent, exists := gcm.Consents[userID]
	if !exists {
		return false, errors.New("user consent not found")
	}

	details, exists := consent.DataTypes[dataType]
	if !exists {
		return false, errors.New("data type consent not found")
	}

	for _, allowedAction := range details.AllowedActions {
		if allowedAction == action {
			return true, nil
		}
	}

	return false, nil
}

// RevokeConsent revokes consent for a user
func (gcm *GranularConsentManager) RevokeConsent(userID string) error {
	gcm.Mutex.Lock()
	defer gcm.Mutex.Unlock()

	if _, exists := gcm.Consents[userID]; !exists {
		return errors.New("user consent not found")
	}

	delete(gcm.Consents, userID)
	return nil
}

// UpdateUserConsent updates the consent preferences for a user
func (gcm *GranularConsentManager) UpdateUserConsent(userID string, dataTypes map[string]ConsentDetails, passphrase string) (*UserConsent, error) {
	gcm.Mutex.Lock()
	defer gcm.Mutex.Unlock()

	consent, exists := gcm.Consents[userID]
	if !exists {
		return nil, errors.New("user consent not found")
	}

	consent.DataTypes = dataTypes
	consent.UpdatedAt = time.Now()

	encryptedConsent, consentHash, err := encryptConsent(consent, passphrase)
	if err != nil {
		return nil, err
	}

	consent.ConsentHash = consentHash

	gcm.Consents[userID] = consent
	return consent, nil
}


// NewImmutableTrailManager initializes a new ImmutableTrailManager
func NewImmutableTrailManager(dbPath string) (*ImmutableTrailManager, error) {
	opts := badger.DefaultOptions(dbPath).WithLoggingLevel(badger.WARNING)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &ImmutableTrailManager{DB: db}, nil
}

// CreateAuditRecord creates a new audit record and adds it to the immutable trail
func (itm *ImmutableTrailManager) CreateAuditRecord(userID, action, description string) (*AuditRecord, error) {
	itm.Mutex.Lock()
	defer itm.Mutex.Unlock()

	var prevHash string
	err := itm.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("last_hash"))
		if err == badger.ErrKeyNotFound {
			prevHash = ""
			return nil
		} else if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			prevHash = string(val)
			return nil
		})
		return err
	})
	if err != nil {
		return nil, err
	}

	timestamp := time.Now()
	record := &AuditRecord{
		Timestamp:   timestamp,
		UserID:      userID,
		Action:      action,
		Description: description,
		PrevHash:    prevHash,
	}
	record.Hash = itm.hashRecord(record)

	err = itm.DB.Update(func(txn *badger.Txn) error {
		recordBytes, err := recordToBytes(record)
		if err != nil {
			return err
		}
		err = txn.Set([]byte(record.Hash), recordBytes)
		if err != nil {
			return err
		}
		err = txn.Set([]byte("last_hash"), []byte(record.Hash))
		return err
	})
	if err != nil {
		return nil, err
	}

	return record, nil
}

// VerifyAuditTrail verifies the integrity of the entire audit trail
func (itm *ImmutableTrailManager) VerifyAuditTrail() (bool, error) {
	itm.Mutex.Lock()
	defer itm.Mutex.Unlock()

	var prevHash string
	err := itm.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("last_hash"))
		if err == badger.ErrKeyNotFound {
			prevHash = ""
			return nil
		} else if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			prevHash = string(val)
			return nil
		})
		return err
	})
	if err != nil {
		return false, err
	}

	var records []*AuditRecord
	err = itm.DB.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 10
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()
			if string(key) == "last_hash" {
				continue
			}
			err := item.Value(func(val []byte) error {
				record, err := bytesToRecord(val)
				if err != nil {
					return err
				}
				records = append(records, record)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	for _, record := range records {
		if record.PrevHash != prevHash {
			return false, nil
		}
		if record.Hash != itm.hashRecord(record) {
			return false, nil
		}
		prevHash = record.Hash
	}
	return true, nil
}

// hashRecord generates a hash for a given audit record
func (itm *ImmutableTrailManager) hashRecord(record *AuditRecord) string {
	recordString := record.Timestamp.String() + record.UserID + record.Action + record.Description + record.PrevHash
	hash := sha256.Sum256([]byte(recordString))
	return hex.EncodeToString(hash[:])
}

// recordToBytes converts an AuditRecord to a byte slice
func recordToBytes(record *AuditRecord) ([]byte, error) {
	return json.Marshal(record)
}

// bytesToRecord converts a byte slice to an AuditRecord
func bytesToRecord(data []byte) (*AuditRecord, error) {
	var record AuditRecord
	err := json.Unmarshal(data, &record)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// Close closes the database connection
func (itm *ImmutableTrailManager) Close() error {
	return itm.DB.Close()
}

// NewPersonalDataVaultsManager initializes a new PersonalDataVaultsManager
func NewPersonalDataVaultsManager(dbPath string) (*PersonalDataVaultsManager, error) {
	opts := badger.DefaultOptions(dbPath).WithLoggingLevel(badger.WARNING)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &PersonalDataVaultsManager{DB: db}, nil
}

// CreatePersonalDataVault creates a new personal data vault for a user
func (pvm *PersonalDataVaultsManager) CreatePersonalDataVault(userID string, password string) (*PersonalDataVault, error) {
	pvm.Mutex.Lock()
	defer pvm.Mutex.Unlock()

	encryptionKey, err := generateEncryptionKey(password)
	if err != nil {
		return nil, err
	}

	vault := &PersonalDataVault{
		UserID:      userID,
		Data:        make(map[string]string),
		EncryptionKey: encryptionKey,
	}

	err = pvm.DB.Update(func(txn *badger.Txn) error {
		vaultBytes, err := vaultToBytes(vault)
		if err != nil {
			return err
		}
		return txn.Set([]byte(userID), vaultBytes)
	})
	if err != nil {
		return nil, err
	}

	return vault, nil
}

// StoreData stores data in the user's personal data vault
func (pvm *PersonalDataVaultsManager) StoreData(userID string, key string, value string, password string) error {
	pvm.Mutex.Lock()
	defer pvm.Mutex.Unlock()

	vault, err := pvm.getPersonalDataVault(userID, password)
	if err != nil {
		return err
	}

	encryptedValue, err := encryptData(value, vault.EncryptionKey)
	if err != nil {
		return err
	}

	vault.Data[key] = encryptedValue

	return pvm.DB.Update(func(txn *badger.Txn) error {
		vaultBytes, err := vaultToBytes(vault)
		if err != nil {
			return err
		}
		return txn.Set([]byte(userID), vaultBytes)
	})
}

// RetrieveData retrieves data from the user's personal data vault
func (pvm *PersonalDataVaultsManager) RetrieveData(userID string, key string, password string) (string, error) {
	pvm.Mutex.Lock()
	defer pvm.Mutex.Unlock()

	vault, err := pvm.getPersonalDataVault(userID, password)
	if err != nil {
		return "", err
	}

	encryptedValue, exists := vault.Data[key]
	if !exists {
		return "", errors.New("data not found")
	}

	return decryptData(encryptedValue, vault.EncryptionKey)
}

// DeletePersonalDataVault deletes a user's personal data vault
func (pvm *PersonalDataVaultsManager) DeletePersonalDataVault(userID string) error {
	pvm.Mutex.Lock()
	defer pvm.Mutex.Unlock()

	return pvm.DB.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(userID))
	})
}

// getPersonalDataVault retrieves and decrypts a user's personal data vault
func (pvm *PersonalDataVaultsManager) getPersonalDataVault(userID string, password string) (*PersonalDataVault, error) {
	var vault *PersonalDataVault

	err := pvm.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(userID))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			vault, err = bytesToVault(val)
			return err
		})
	})
	if err != nil {
		return nil, err
	}

	encryptionKey, err := generateEncryptionKey(password)
	if err != nil {
		return nil, err
	}

	if !equalKeys(encryptionKey, vault.EncryptionKey) {
		return nil, errors.New("invalid password")
	}

	return vault, nil
}

// generateEncryptionKey generates an encryption key from the given password
func generateEncryptionKey(password string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}
	return scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
}

// encryptData encrypts the given data using AES encryption
func encryptData(data string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// decryptData decrypts the given data using AES decryption
func decryptData(data string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// vaultToBytes converts a PersonalDataVault to a byte slice
func vaultToBytes(vault *PersonalDataVault) ([]byte, error) {
	return json.Marshal(vault)
}

// bytesToVault converts a byte slice to a PersonalDataVault
func bytesToVault(data []byte) (*PersonalDataVault, error) {
	var vault PersonalDataVault
	err := json.Unmarshal(data, &vault)
	if err != nil {
		return nil, err
	}
	return &vault, nil
}

// equalKeys compares two encryption keys for equality
func equalKeys(key1, key2 []byte) bool {
	if len(key1) != len(key2) {
		return false
	}
	for i := range key1 {
		if key1[i] != key2[i] {
			return false
		}
	}
	return true
}

// Close closes the database connection
func (pvm *PersonalDataVaultsManager) Close() error {
	return pvm.DB.Close()
}


// GenerateSmartContractID generates a unique smart contract ID
func GenerateSmartContractID(owner string) string {
	hash := sha256.New()
	hash.Write([]byte(owner + time.Now().String()))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

// NewSmartContract creates a new smart contract
func NewSmartContract(owner string) *SmartContract {
	return &SmartContract{
		ID:              GenerateSmartContractID(owner),
		Owner:           owner,
		PrivacyPolicies: []PrivacyPolicy{},
		AccessLogs:      []AccessLog{},
	}
}

// AddPrivacyPolicy adds a new privacy policy to the smart contract
func (sc *SmartContract) AddPrivacyPolicy(policy PrivacyPolicy) {
	sc.PrivacyPolicies = append(sc.PrivacyPolicies, policy)
}

// EncryptData encrypts data using AES encryption
func EncryptData(data []byte, passphrase string) (string, error) {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using AES decryption
func DecryptData(encryptedData string, passphrase string) ([]byte, error) {
	data, err := base64.URLEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// createHash creates a hash from a passphrase
func createHash(key string) string {
	hash := sha256.Sum256([]byte(key))
	return base64.URLEncoding.EncodeToString(hash[:])
}

// Argon2Hash generates a secure hash using Argon2
func Argon2Hash(password string, salt []byte) string {
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return base64.URLEncoding.EncodeToString(hash)
}

// SecureRandomSalt generates a secure random salt
func SecureRandomSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// CheckAccess evaluates if a user has access to a resource based on the smart contract
func (sc *SmartContract) CheckAccess(userID string, role string, resource string) bool {
	currentTime := time.Now()
	for _, policy := range sc.PrivacyPolicies {
		if currentTime.After(policy.ValidFrom) && currentTime.Before(policy.ValidUntil) {
			for _, r := range policy.Roles {
				if r == role {
					for _, perm := range policy.Permissions[r] {
						if perm == resource {
							sc.logAccess(userID, resource, true)
							return true
						}
					}
				}
			}
		}
	}
	sc.logAccess(userID, resource, false)
	return false
}

// logAccess logs an access attempt
func (sc *SmartContract) logAccess(userID string, resource string, granted bool) {
	sc.AccessLogs = append(sc.AccessLogs, AccessLog{
		Timestamp: time.Now(),
		UserID:    userID,
		Action:    "Access Attempt",
		Resource:  resource,
		Granted:   granted,
	})
}

// NewDataMasking initializes a new DataMasking service with a given key
func NewDataMasking(key []byte) *DataMasking {
    return &DataMasking{MaskingKey: key}
}

// MaskData masks the given data using AES encryption
func (dm *DataMasking) MaskData(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(dm.MaskingKey)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, aes.BlockSize+len(data))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

    return ciphertext, nil
}

// UnmaskData unmasks the given data using AES decryption
func (dm *DataMasking) UnmaskData(ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(dm.MaskingKey)
    if err != nil {
        return nil, err
    }

    if len(ciphertext) < aes.BlockSize {
        return nil, fmt.Errorf("ciphertext too short")
    }
    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    return ciphertext, nil
}

// UserPrivacyManager manages the privacy settings for all users.
type UserPrivacyManager struct {
    users map[string]*UserPrivacySettings
    mu    sync.RWMutex
}

// NewUserPrivacyManager creates a new UserPrivacyManager
func NewUserPrivacyManager() *UserPrivacyManager {
    return &UserPrivacyManager{
        users: make(map[string]*UserPrivacySettings),
    }
}

// SetPrivacySettings sets the privacy settings for a user.
func (upm *UserPrivacyManager) SetPrivacySettings(userID string, settings UserPrivacySettings) {
    upm.mu.Lock()
    defer upm.mu.Unlock()

    upm.users[userID] = &settings
}

// GetPrivacySettings gets the privacy settings for a user.
func (upm *UserPrivacyManager) GetPrivacySettings(userID string) (*UserPrivacySettings, bool) {
    upm.mu.RLock()
    defer upm.mu.RUnlock()

    settings, exists := upm.users[userID]
    return settings, exists
}

// UpdatePrivacySettings updates specific privacy settings for a user.
func (upm *UserPrivacyManager) UpdatePrivacySettings(userID string, newPrefs map[string]interface{}) error {
    upm.mu.RLock()
    userSettings, exists := upm.users[userID]
    upm.mu.RUnlock()

    if !exists {
        return fmt.Errorf("user not found")
    }

    userSettings.SettingsMutex.Lock()
    defer userSettings.SettingsMutex.Unlock()

    for key, value := range newPrefs {
        userSettings.PrivacyPrefs[key] = value
    }

    return nil
}

// HandleSetPrivacySettings is an HTTP handler for setting privacy settings.
func (upm *UserPrivacyManager) HandleSetPrivacySettings(w http.ResponseWriter, r *http.Request) {
    var settings UserPrivacySettings
    if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    upm.SetPrivacySettings(settings.UserID, settings)
    w.WriteHeader(http.StatusOK)
}

// HandleGetPrivacySettings is an HTTP handler for getting privacy settings.
func (upm *UserPrivacyManager) HandleGetPrivacySettings(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("user_id")
    if userID == "" {
        http.Error(w, "Missing user_id parameter", http.StatusBadRequest)
        return
    }

    settings, exists := upm.GetPrivacySettings(userID)
    if !exists {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    if err := json.NewEncoder(w).Encode(settings); err != nil {
        http.Error(w, "Error encoding response", http.StatusInternalServerError)
        return
    }
}

// GenerateMaskingKey generates a secure masking key using scrypt
func GenerateMaskingKey(password, salt []byte) ([]byte, error) {
    key, err := scrypt.Key(password, salt, 16384, 8, 1, 32)
    if err != nil {
        return nil, err
    }
    return key, nil
}


// NewUserPrivacyControl creates a new instance of UserPrivacyControl.
func NewUserPrivacyControl(salt []byte, params *KeyDerivationParams) (*UserPrivacyControl, error) {
	upc := &UserPrivacyControl{
		userData:            make(map[string]*UserData),
		salt:                salt,
		keyDerivationParams: params,
	}

	// Derive encryption key
	key, err := scrypt.Key([]byte("passphrase"), salt, params.N, params.R, params.P, params.KeyLen)
	if err != nil {
		return nil, err
	}
	upc.encryptionKey = key

	return upc, nil
}

// AddOrUpdateUserData encrypts and adds or updates user data.
func (upc *UserPrivacyControl) AddOrUpdateUserData(userID string, data []byte, prefs PrivacyPreferences) error {
	upc.mu.Lock()
	defer upc.mu.Unlock()

	encryptedData, err := upc.encryptData(data)
	if err != nil {
		return err
	}

	upc.userData[userID] = &UserData{
		EncryptedData: encryptedData,
		PrivacyPrefs:  prefs,
	}

	return nil
}

// GetUserData retrieves and decrypts user data based on access control settings.
func (upc *UserPrivacyControl) GetUserData(userID, accessorID string) ([]byte, error) {
	upc.mu.RLock()
	defer upc.mu.RUnlock()

	userData, exists := upc.userData[userID]
	if !exists {
		return nil, errors.New("user data not found")
	}

	// Check access control
	canAccess, ok := userData.PrivacyPrefs.AccessControl[accessorID]
	if !ok || !canAccess {
		return nil, errors.New("access denied")
	}

	return upc.decryptData(userData.EncryptedData)
}

// UpdatePrivacyPreferences updates the privacy preferences for a given user.
func (upc *UserPrivacyControl) UpdatePrivacyPreferences(userID string, prefs PrivacyPreferences) error {
	upc.mu.Lock()
	defer upc.mu.Unlock()

	userData, exists := upc.userData[userID]
	if !exists {
		return errors.New("user data not found")
	}

	userData.PrivacyPrefs = prefs
	return nil
}

// encryptData encrypts the given data using AES encryption.
func (upc *UserPrivacyControl) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(upc.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptData decrypts the given data using AES encryption.
func (upc *UserPrivacyControl) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(upc.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateSalt generates a new random salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// HashPassword hashes a password with a given salt.
func HashPassword(password string, salt []byte, params *KeyDerivationParams) (string, error) {
	hash, err := scrypt.Key([]byte(password), salt, params.N, params.R, params.P, params.KeyLen)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash), nil
}

// VerifyPassword verifies a password against a hashed value.
func VerifyPassword(password, hashedPassword string, salt []byte, params *KeyDerivationParams) (bool, error) {
	hash, err := HashPassword(password, salt, params)
	if err != nil {
		return false, err
	}
	return hash == hashedPassword, nil
}


