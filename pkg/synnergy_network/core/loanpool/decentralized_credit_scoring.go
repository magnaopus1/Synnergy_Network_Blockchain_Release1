package decentralized_credit_scoring

import (
    "encoding/json"
    "errors"
    "time"

    "github.com/synnergy_network_blockchain/pkg/synnergy_network/core/common"

)

func (acd *common.AlternativeCreditData) Validate() error {
    if acd.UserID == "" {
        return errors.New("user ID cannot be empty")
    }
    if len(acd.SocialMediaActivity) == 0 && len(acd.UtilityPayments) == 0 && len(acd.RentalHistory) == 0 && len(acd.BehavioralAnalytics) == 0 {
        return errors.New("at least one data source must be provided")
    }
    return nil
}

func (acd *AlternativeCreditData) EncryptData(encryptionKey string) (string, error) {
    dataBytes, err := json.Marshal(acd)
    if err != nil {
        return "", err
    }

    encryptedData, err := encryption.EncryptAES(dataBytes, encryptionKey)
    if err != nil {
        return "", err
    }

    return encryptedData, nil
}

func (acd *AlternativeCreditData) DecryptData(encryptedData, encryptionKey string) error {
    decryptedBytes, err := encryption.DecryptAES(encryptedData, encryptionKey)
    if err != nil {
        return err
    }

    err = json.Unmarshal(decryptedBytes, acd)
    if err != nil {
        return err
    }

    return nil
}

func (acd *AlternativeCreditData) SaveToBlockchain() error {
    if err := acd.Validate(); err != nil {
        return err
    }

    dataBytes, err := json.Marshal(acd)
    if err != nil {
        return err
    }

    txn := blockchain.NewTransaction(acd.UserID, "save_alternative_credit_data", dataBytes)
    if err := blockchain.ProcessTransaction(txn); err != nil {
        return err
    }

    logger.Info("Alternative credit data saved to blockchain for user ID:", acd.UserID)
    return nil
}

func RetrieveAlternativeCreditData(userID string) (*AlternativeCreditData, error) {
    txn, err := blockchain.GetTransactionByKey(userID, "retrieve_alternative_credit_data")
    if err != nil {
        return nil, err
    }

    var acd AlternativeCreditData
    if err := json.Unmarshal(txn.Data, &acd); err != nil {
        return nil, err
    }

    return &acd, nil
}

func UpdateAlternativeCreditData(userID string, updatedData map[string]interface{}) error {
    acd, err := RetrieveAlternativeCreditData(userID)
    if err != nil {
        return err
    }

    for key, value := range updatedData {
        switch key {
        case "social_media_activity":
            if v, ok := value.(map[string]interface{}); ok {
                acd.SocialMediaActivity = v
            }
        case "utility_payments":
            if v, ok := value.(map[string]float64); ok {
                acd.UtilityPayments = v
            }
        case "rental_history":
            if v, ok := value.(map[string]float64); ok {
                acd.RentalHistory = v
            }
        case "behavioral_analytics":
            if v, ok := value.(map[string]interface{}); ok {
                acd.BehavioralAnalytics = v
            }
        }
    }

    acd.LastUpdated = time.Now()

    return acd.SaveToBlockchain()
}


// NewBehavioralAnalytics initializes a new instance of BehavioralAnalytics
func NewBehavioralAnalytics(userID string) *BehavioralAnalytics {
    return &BehavioralAnalytics{
        UserID: userID,
        TransactionHistory: make([]models.Transaction, 0),
        PaymentPatterns:    make([]PaymentPattern, 0),
        RiskProfile:        models.RiskProfile{},
    }
}

// AnalyzeBehavior analyzes user behavior to update the risk profile
func (ba *BehavioralAnalytics) AnalyzeBehavior() error {
    ba.TransactionHistory = fetchTransactionHistory(ba.UserID)
    ba.PaymentPatterns = identifyPaymentPatterns(ba.TransactionHistory)
    ba.RiskProfile = calculateRiskProfile(ba.PaymentPatterns)
    return nil
}

// fetchTransactionHistory fetches the transaction history for a user
func fetchTransactionHistory(userID string) []models.Transaction {
    // Fetch transaction history from blockchain
    transactions, err := blockchain.GetTransactionHistory(userID)
    if err != nil {
        utils.LogError(err)
        return []models.Transaction{}
    }
    return transactions
}

// identifyPaymentPatterns identifies payment patterns from transaction history
func identifyPaymentPatterns(transactions []models.Transaction) []PaymentPattern {
    patterns := make([]PaymentPattern, 0)
    // AI/ML models to identify patterns
    paymentPatterns := ai.IdentifyPaymentPatterns(transactions)
    for _, pattern := range paymentPatterns {
        patterns = append(patterns, PaymentPattern{
            PatternType:  pattern.Type,
            Description:  pattern.Description,
            Occurrences:  pattern.Occurrences,
            LastObserved: pattern.LastObserved,
            RiskImpact:   pattern.RiskImpact,
        })
    }
    return patterns
}

// calculateRiskProfile calculates the risk profile based on payment patterns
func calculateRiskProfile(patterns []PaymentPattern) models.RiskProfile {
    riskProfile := models.RiskProfile{}
    totalRiskImpact := big.NewInt(0)
    for _, pattern := range patterns {
        totalRiskImpact = new(big.Int).Add(totalRiskImpact, pattern.RiskImpact)
    }
    riskProfile.TotalRiskImpact = totalRiskImpact
    riskProfile.Score = ai.CalculateCreditScore(totalRiskImpact)
    return riskProfile
}

// UpdateRiskProfile updates the risk profile on the blockchain
func (ba *BehavioralAnalytics) UpdateRiskProfile() error {
    err := blockchain.UpdateRiskProfile(ba.UserID, ba.RiskProfile)
    if err != nil {
        utils.LogError(err)
        return err
    }
    return nil
}

// GenerateReport generates a detailed report of the behavioral analysis
func (ba *BehavioralAnalytics) GenerateReport() (string, error) {
    report, err := utils.GenerateReport(ba.UserID, ba.TransactionHistory, ba.PaymentPatterns, ba.RiskProfile)
    if err != nil {
        utils.LogError(err)
        return "", err
    }
    return report, nil
}

var (
	creditScores = make(map[string]*CreditScore)
	mu           sync.Mutex
)

// UpdateCreditScore updates the credit score of a user
func UpdateCreditScore(userID string, transaction Transaction, behavior BehavioralData) error {
	mu.Lock()
	defer mu.Unlock()

	cs, exists := creditScores[userID]
	if !exists {
		cs = &CreditScore{
			UserID:             userID,
			TransactionHistory: []Transaction{},
			BehavioralData:     BehavioralData{},
		}
		creditScores[userID] = cs
	}

	cs.TransactionHistory = append(cs.TransactionHistory, transaction)
	cs.BehavioralData = behavior
	cs.LastUpdated = time.Now().Unix()

	score, err := ai.CalculateCreditScore(cs.TransactionHistory, cs.BehavioralData)
	if err != nil {
		return errors.Wrap(err, "failed to calculate credit score")
	}
	cs.Score = score

	return saveCreditScore(cs)
}

// GetCreditScore retrieves the credit score of a user
func GetCreditScore(userID string) (*CreditScore, error) {
	mu.Lock()
	defer mu.Unlock()

	cs, exists := creditScores[userID]
	if !exists {
		return nil, fmt.Errorf("credit score not found for user ID: %s", userID)
	}
	return cs, nil
}

// MonitorCreditScores periodically checks and updates credit scores for all users
func MonitorCreditScores() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mu.Lock()
			for _, cs := range creditScores {
				transactionData, err := blockchain.FetchUserTransactions(cs.UserID)
				if err != nil {
					fmt.Printf("Error fetching transactions for user %s: %v\n", cs.UserID, err)
					continue
				}
				behavioralData, err := ai.FetchBehavioralData(cs.UserID)
				if err != nil {
					fmt.Printf("Error fetching behavioral data for user %s: %v\n", cs.UserID, err)
					continue
				}
				UpdateCreditScore(cs.UserID, transactionData, behavioralData)
			}
			mu.Unlock()
		}
	}
}

// saveCreditScore saves the credit score to a persistent storage
func saveCreditScore(cs *CreditScore) error {
	data, err := json.Marshal(cs)
	if err != nil {
		return errors.Wrap(err, "failed to marshal credit score")
	}

	err = utils.SaveToFile(cs.UserID+"_credit_score.json", data)
	if err != nil {
		return errors.Wrap(err, "failed to save credit score to file")
	}
	return nil
}

// GenerateCreditReport generates a credit report for a given user ID.
func GenerateCreditReport(userID string, score int, details string) CreditReport {
    return CreditReport{
        UserID:        userID,
        Score:         score,
        ReportDetails: details,
        Timestamp:     time.Now(),
    }
}

// EncryptReport encrypts the credit report using AES encryption.
func EncryptReport(report CreditReport, passphrase string) (SecureCreditReport, error) {
    data, err := json.Marshal(report)
    if err != nil {
        return SecureCreditReport{}, fmt.Errorf("failed to marshal report: %v", err)
    }

    key, salt, err := deriveKeyFromPassphrase(passphrase)
    if err != nil {
        return SecureCreditReport{}, fmt.Errorf("failed to derive key: %v", err)
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return SecureCreditReport{}, fmt.Errorf("failed to create cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return SecureCreditReport{}, fmt.Errorf("failed to create GCM: %v", err)
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return SecureCreditReport{}, fmt.Errorf("failed to generate nonce: %v", err)
    }

    encrypted := gcm.Seal(nonce, nonce, data, nil)
    return SecureCreditReport{UserID: report.UserID, Encrypted: encrypted}, nil
}

// DecryptReport decrypts the secure credit report using AES encryption.
func DecryptReport(secReport SecureCreditReport, passphrase string) (CreditReport, error) {
    key, _, err := deriveKeyFromPassphrase(passphrase)
    if err != nil {
        return CreditReport{}, fmt.Errorf("failed to derive key: %v", err)
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return CreditReport{}, fmt.Errorf("failed to create cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return CreditReport{}, fmt.Errorf("failed to create GCM: %v", err)
    }

    nonceSize := gcm.NonceSize()
    if len(secReport.Encrypted) < nonceSize {
        return CreditReport{}, fmt.Errorf("invalid encrypted data")
    }

    nonce, ciphertext := secReport.Encrypted[:nonceSize], secReport.Encrypted[nonceSize:]
    data, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return CreditReport{}, fmt.Errorf("failed to decrypt data: %v", err)
    }

    var report CreditReport
    if err := json.Unmarshal(data, &report); err != nil {
        return CreditReport{}, fmt.Errorf("failed to unmarshal report: %v", err)
    }

    return report, nil
}

// deriveKeyFromPassphrase derives a secure key from a passphrase using Scrypt.
func deriveKeyFromPassphrase(passphrase string) (key, salt []byte, err error) {
    salt = make([]byte, 16)
    if _, err = io.ReadFull(rand.Reader, salt); err != nil {
        return nil, nil, fmt.Errorf("failed to generate salt: %v", err)
    }

    key, err = scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to derive key: %v", err)
    }

    return key, salt, nil
}

// SaveReport saves the encrypted credit report to a file.
func SaveReport(filename string, report SecureCreditReport) error {
    file, err := os.Create(filename)
    if err != nil {
        return fmt.Errorf("failed to create file: %v", err)
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    if err := encoder.Encode(report); err != nil {
        return fmt.Errorf("failed to encode report: %v", err)
    }

    return nil
}

// LoadReport loads the encrypted credit report from a file.
func LoadReport(filename string) (SecureCreditReport, error) {
    file, err := os.Open(filename)
    if err != nil {
        return SecureCreditReport{}, fmt.Errorf("failed to open file: %v", err)
    }
    defer file.Close()

    var report SecureCreditReport
    decoder := json.NewDecoder(file)
    if err := decoder.Decode(&report); err != nil {
        return SecureCreditReport{}, fmt.Errorf("failed to decode report: %v", err)
    }

    return report, nil
}

// HashUserID hashes a user ID for secure storage and comparison.
func HashUserID(userID string) string {
    hash := sha256.Sum256([]byte(userID))
    return fmt.Sprintf("%x", hash)
}

// GenerateUniqueID generates a unique ID for a new credit report.
func GenerateUniqueID() string {
    return uuid.New().String()
}

// CalculateScore calculates a credit score based on basic credit data.
func (a BasicCreditScoreAlgorithm) CalculateScore(userID string, data CreditData) (int, error) {
    score := 600 // Base score

    // Analyze transaction history
    for _, tx := range data.TransactionHistory {
        if tx.Type == "payment" && tx.Amount > 0 {
            score += 1
        } else if tx.Type == "loan" && tx.Amount > 0 {
            score -= 1
        }
    }

    // Analyze behavioral data
    score += int(data.BehavioralData.PaymentPunctuality * 100)
    for _, amount := range data.BehavioralData.SpendingPatterns {
        if amount > 1000 {
            score -= 5
        } else {
            score += 2
        }
    }
    score += int(data.BehavioralData.IncomeStability * 50)

    // Analyze external data
    for _, report := range data.ExternalData.CreditReports {
        score += report.Score / 10
    }
    for _, activity := range data.ExternalData.SocialMedia {
        score += int(activity * 5)
    }
    for _, bill := range data.ExternalData.UtilityBills {
        if bill > 100 {
            score -= 2
        } else {
            score += 1
        }
    }

    return score, nil
}

// AdvancedCreditScoreAlgorithm implements a more advanced credit scoring algorithm using AI/ML.
type AdvancedCreditScoreAlgorithm struct{}

// CalculateScore calculates a credit score using advanced AI/ML techniques.
func (a AdvancedCreditScoreAlgorithm) CalculateScore(userID string, data CreditData) (int, error) {
    // Placeholder for AI/ML-based scoring
    // In a real-world scenario, this would involve machine learning models trained on historical data.
    score := 700 // Base score

    // Add logic for AI/ML model inference
    // For example, integrating with a pre-trained model for risk assessment

    return score, nil
}

// EncryptCreditData encrypts the credit data using AES encryption.
func EncryptCreditData(data CreditData, passphrase string) ([]byte, error) {
    jsonData, err := json.Marshal(data)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal data: %v", err)
    }

    key, salt, err := deriveKeyFromPassphrase(passphrase)
    if err != nil {
        return nil, fmt.Errorf("failed to derive key: %v", err)
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("failed to create GCM: %v", err)
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %v", err)
    }

    encrypted := gcm.Seal(nonce, nonce, jsonData, nil)
    return encrypted, nil
}

// DecryptCreditData decrypts the encrypted credit data using AES encryption.
func DecryptCreditData(encryptedData []byte, passphrase string) (CreditData, error) {
    key, _, err := deriveKeyFromPassphrase(passphrase)
    if err != nil {
        return CreditData{}, fmt.Errorf("failed to derive key: %v", err)
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return CreditData{}, fmt.Errorf("failed to create cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return CreditData{}, fmt.Errorf("failed to create GCM: %v", err)
    }

    nonceSize := gcm.NonceSize()
    if len(encryptedData) < nonceSize {
        return CreditData{}, fmt.Errorf("invalid encrypted data")
    }

    nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
    jsonData, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return CreditData{}, fmt.Errorf("failed to decrypt data: %v", err)
    }

    var data CreditData
    if err := json.Unmarshal(jsonData, &data); err != nil {
        return CreditData{}, fmt.Errorf("failed to unmarshal data: %v", err)
    }

    return data, nil
}

// deriveKeyFromPassphrase derives a secure key from a passphrase using Argon2.
func deriveKeyFromPassphrase(passphrase string) (key, salt []byte, err error) {
    salt = make([]byte, 16)
    if _, err = io.ReadFull(rand.Reader, salt); err != nil {
        return nil, nil, fmt.Errorf("failed to generate salt: %v", err)
    }

    key = argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
    return key, salt, nil
}

// HashData securely hashes the data using SHA-256.
func HashData(data []byte) []byte {
    hash := sha256.Sum256(data)
    return hash[:]
}

// NewIdentityManager creates a new instance of IdentityManager.
func NewIdentityManager() *IdentityManager {
    return &IdentityManager{users: make(map[string]User)}
}

// RegisterUser registers a new user in the system.
func (im *IdentityManager) RegisterUser(phoneNumber, email, nodeType string) (User, error) {
    synID := generateSynID()
    userID := uuid.New().String()
    walletID := generateWalletID()
    publicKey := generatePublicKey()
    recoveryKey := generateRecoveryKey()

    user := User{
        SynID:       synID,
        PhoneNumber: phoneNumber,
        Email:       email,
        UserID:      userID,
        NodeType:    nodeType,
        WalletID:    walletID,
        PublicKey:   publicKey,
        RecoveryKey: recoveryKey,
        CreatedAt:   time.Now(),
    }

    im.users[synID] = user

    return user, nil
}

// GetUser retrieves a user's information based on their SynID.
func (im *IdentityManager) GetUser(synID string) (User, error) {
    user, exists := im.users[synID]
    if !exists {
        return User{}, fmt.Errorf("user with SynID %s not found", synID)
    }
    return user, nil
}

// VerifyUser verifies a user's identity based on their SynID and a provided recovery key.
func (im *IdentityManager) VerifyUser(synID, recoveryKey string) (bool, error) {
    user, exists := im.users[synID]
    if !exists {
        return false, fmt.Errorf("user with SynID %s not found", synID)
    }
    return user.RecoveryKey == recoveryKey, nil
}

// generateSynID generates a new SYN900 ID token.
func generateSynID() string {
    return "SYN" + uuid.New().String()
}

// generateWalletID generates a new wallet ID.
func generateWalletID() string {
    return "WAL" + uuid.New().String()
}

// generatePublicKey generates a new public key.
func generatePublicKey() string {
    return "PUB" + uuid.New().String()
}

// generateRecoveryKey generates a new recovery key using Argon2.
func generateRecoveryKey() string {
    key := argon2.IDKey([]byte(uuid.New().String()), []byte("somesalt"), 1, 64*1024, 4, 32)
    return fmt.Sprintf("%x", key)
}

// EncryptUserData encrypts the user's data using AES encryption.
func EncryptUserData(user User, passphrase string) ([]byte, error) {
    data, err := json.Marshal(user)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal user data: %v", err)
    }

    key, salt, err := deriveKeyFromPassphrase(passphrase)
    if err != nil {
        return nil, fmt.Errorf("failed to derive key: %v", err)
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("failed to create GCM: %v", err)
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %v", err)
    }

    encrypted := gcm.Seal(nonce, nonce, data, nil)
    return append(salt, encrypted...), nil
}

// DecryptUserData decrypts the encrypted user data using AES encryption.
func DecryptUserData(encryptedData []byte, passphrase string) (User, error) {
    salt := encryptedData[:16]
    encryptedData = encryptedData[16:]

    key, _, err := deriveKeyFromPassphraseWithSalt(passphrase, salt)
    if err != nil {
        return User{}, fmt.Errorf("failed to derive key: %v", err)
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return User{}, fmt.Errorf("failed to create cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return User{}, fmt.Errorf("failed to create GCM: %v", err)
    }

    nonceSize := gcm.NonceSize()
    if len(encryptedData) < nonceSize {
        return User{}, fmt.Errorf("invalid encrypted data")
    }

    nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
    data, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return User{}, fmt.Errorf("failed to decrypt data: %v", err)
    }

    var user User
    if err := json.Unmarshal(data, &user); err != nil {
        return User{}, fmt.Errorf("failed to unmarshal user data: %v", err)
    }

    return user, nil
}

// deriveKeyFromPassphrase derives a secure key from a passphrase using Argon2.
func deriveKeyFromPassphrase(passphrase string) (key, salt []byte, err error) {
    salt = make([]byte, 16)
    if _, err = io.ReadFull(rand.Reader, salt); err != nil {
        return nil, nil, fmt.Errorf("failed to generate salt: %v", err)
    }

    key = argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
    return key, salt, nil
}

// deriveKeyFromPassphraseWithSalt derives a secure key from a passphrase using Argon2 with a given salt.
func deriveKeyFromPassphraseWithSalt(passphrase string, salt []byte) (key, newSalt []byte, err error) {
    key = argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
    return key, salt, nil
}

// HashData securely hashes the data using SHA-256.
func HashData(data []byte) []byte {
    hash := sha256.Sum256(data)
    return hash[:]
}

// RecoveryMnemonic generates a recovery mnemonic for the user.
func RecoveryMnemonic() string {
    mnemonic := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, mnemonic); err != nil {
        panic(fmt.Errorf("failed to generate recovery mnemonic: %v", err))
    }
    return fmt.Sprintf("%x", mnemonic)
}

// UserLogin logs a user into the system using their SynID and passphrase.
func (im *IdentityManager) UserLogin(synID, passphrase string) (User, error) {
    encryptedData, err := im.GetEncryptedUserData(synID)
    if err != nil {
        return User{}, err
    }
    user, err := DecryptUserData(encryptedData, passphrase)
    if err != nil {
        return User{}, fmt.Errorf("failed to login: %v", err)
    }
    return user, nil
}

// GetEncryptedUserData retrieves the encrypted user data for the given SynID.
func (im *IdentityManager) GetEncryptedUserData(synID string) ([]byte, error) {
    user, exists := im.users[synID]
    if !exists {
        return nil, errors.New("user not found")
    }
    passphrase := "securePassphrase" // Replace with an actual method to retrieve the passphrase
    encryptedData, err := EncryptUserData(user, passphrase)
    if err != nil {
        return nil, fmt.Errorf("failed to encrypt user data: %v", err)
    }
    return encryptedData, nil
}

// NewOnChainCreditScoring creates a new instance of OnChainCreditScoring.
func NewOnChainCreditScoring() *OnChainCreditScoring {
    return &OnChainCreditScoring{scores: make(map[string]CreditScore)}
}

// CalculateAndStoreScore calculates a user's credit score and stores it on-chain.
func (ocs *OnChainCreditScoring) CalculateAndStoreScore(userID string, data CreditData) (CreditScore, error) {
    score, err := calculateScore(data)
    if err != nil {
        return CreditScore{}, fmt.Errorf("failed to calculate score: %v", err)
    }

    dataHash := hashData(data)
    creditScore := CreditScore{
        UserID:    userID,
        Score:     score,
        Timestamp: time.Now(),
        DataHash:  dataHash,
    }

    ocs.scores[userID] = creditScore
    return creditScore, nil
}

// GetCreditScore retrieves a user's credit score.
func (ocs *OnChainCreditScoring) GetCreditScore(userID string) (CreditScore, error) {
    score, exists := ocs.scores[userID]
    if !exists {
        return CreditScore{}, fmt.Errorf("credit score for user %s not found", userID)
    }
    return score, nil
}

// calculateScore calculates a credit score based on provided credit data.
func calculateScore(data CreditData) (int, error) {
    // Implement credit scoring logic here, using CreditData structure.
    score := 700 // Example base score
    // Add more logic to calculate the score based on data.
    return score, nil
}

// hashData securely hashes the credit data using SHA-256.
func hashData(data CreditData) string {
    jsonData, err := json.Marshal(data)
    if err != nil {
        panic(fmt.Errorf("failed to marshal data: %v", err))
    }
    hash := sha256.Sum256(jsonData)
    return fmt.Sprintf("%x", hash)
}

// EncryptCreditData encrypts the credit data using AES encryption.
func EncryptCreditData(data CreditData, passphrase string) ([]byte, error) {
    jsonData, err := json.Marshal(data)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal data: %v", err)
    }

    key, salt, err := deriveKeyFromPassphrase(passphrase)
    if err != nil {
        return nil, fmt.Errorf("failed to derive key: %v", err)
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("failed to create GCM: %v", err)
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %v", err)
    }

    encrypted := gcm.Seal(nonce, nonce, jsonData, nil)
    return append(salt, encrypted...), nil
}

// DecryptCreditData decrypts the encrypted credit data using AES encryption.
func DecryptCreditData(encryptedData []byte, passphrase string) (CreditData, error) {
    salt := encryptedData[:16]
    encryptedData = encryptedData[16:]

    key, _, err := deriveKeyFromPassphraseWithSalt(passphrase, salt)
    if err != nil {
        return CreditData{}, fmt.Errorf("failed to derive key: %v", err)
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return CreditData{}, fmt.Errorf("failed to create cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return CreditData{}, fmt.Errorf("failed to create GCM: %v", err)
    }

    nonceSize := gcm.NonceSize()
    if len(encryptedData) < nonceSize {
        return CreditData{}, fmt.Errorf("invalid encrypted data")
    }

    nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
    jsonData, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return CreditData{}, fmt.Errorf("failed to decrypt data: %v", err)
    }

    var data CreditData
    if err := json.Unmarshal(jsonData, &data); err != nil {
        return CreditData{}, fmt.Errorf("failed to unmarshal data: %v", err)
    }

    return data, nil
}

// deriveKeyFromPassphrase derives a secure key from a passphrase using Argon2.
func deriveKeyFromPassphrase(passphrase string) (key, salt []byte, err error) {
    salt = make([]byte, 16)
    if _, err = io.ReadFull(rand.Reader, salt); err != nil {
        return nil, nil, fmt.Errorf("failed to generate salt: %v", err)
    }

    key = argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
    return key, salt, nil
}

// deriveKeyFromPassphraseWithSalt derives a secure key from a passphrase using Argon2 with a given salt.
func deriveKeyFromPassphraseWithSalt(passphrase string, salt []byte) (key, newSalt []byte, err error) {
    key = argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
    return key, salt, nil
}

// NewPrivacyPreservingScoring creates a new instance of PrivacyPreservingScoring.
func NewPrivacyPreservingScoring() *PrivacyPreservingScoring {
    return &PrivacyPreservingScoring{scores: make(map[string]EncryptedScore)}
}

// GenerateAndStoreScore generates a user's credit score, encrypts it, and stores it in the system.
func (pps *PrivacyPreservingScoring) GenerateAndStoreScore(userID string, data CreditData, passphrase string) (EncryptedScore, error) {
    score, err := calculateScore(data)
    if err != nil {
        return EncryptedScore{}, fmt.Errorf("failed to calculate score: %v", err)
    }

    jsonData, err := json.Marshal(score)
    if err != nil {
        return EncryptedScore{}, fmt.Errorf("failed to marshal score data: %v", err)
    }

    encryptedData, salt, nonce, err := encryptData(jsonData, passphrase)
    if err != nil {
        return EncryptedScore{}, fmt.Errorf("failed to encrypt data: %v", err)
    }

    encryptedScore := EncryptedScore{
        UserID: userID,
        Data:   encryptedData,
        Salt:   salt,
        Nonce:  nonce,
    }

    pps.scores[userID] = encryptedScore
    return encryptedScore, nil
}

// GetDecryptedScore retrieves and decrypts a user's credit score.
func (pps *PrivacyPreservingScoring) GetDecryptedScore(userID, passphrase string) (CreditScore, error) {
    encryptedScore, exists := pps.scores[userID]
    if !exists {
        return CreditScore{}, fmt.Errorf("score for user %s not found", userID)
    }

    decryptedData, err := decryptData(encryptedScore.Data, encryptedScore.Salt, encryptedScore.Nonce, passphrase)
    if err != nil {
        return CreditScore{}, fmt.Errorf("failed to decrypt data: %v", err)
    }

    var score CreditScore
    if err := json.Unmarshal(decryptedData, &score); err != nil {
        return CreditScore{}, fmt.Errorf("failed to unmarshal data: %v", err)
    }

    return score, nil
}

// calculateScore calculates a credit score based on provided credit data.
func calculateScore(data CreditData) (CreditScore, error) {
    // Implement the credit scoring logic based on the data
    score := 700 // Example base score
    // Add more logic to calculate the score based on the data
    return CreditScore{
        UserID:    data.UserID,
        Score:     score,
        Timestamp: time.Now(),
        DataHash:  hashData(data),
    }, nil
}

// hashData securely hashes the credit data using SHA-256.
func hashData(data CreditData) string {
    jsonData, err := json.Marshal(data)
    if err != nil {
        panic(fmt.Errorf("failed to marshal data: %v", err))
    }
    hash := sha256.Sum256(jsonData)
    return fmt.Sprintf("%x", hash)
}

// encryptData encrypts the data using AES encryption with Argon2 for key derivation.
func encryptData(data []byte, passphrase string) ([]byte, []byte, []byte, error) {
    salt := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return nil, nil, nil, fmt.Errorf("failed to generate salt: %v", err)
    }

    key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, nil, nil, fmt.Errorf("failed to create cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, nil, nil, fmt.Errorf("failed to create GCM: %v", err)
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, nil, nil, fmt.Errorf("failed to generate nonce: %v", err)
    }

    encryptedData := gcm.Seal(nonce, nonce, data, nil)
    return encryptedData, salt, nonce, nil
}

// decryptData decrypts the data using AES encryption with Argon2 for key derivation.
func decryptData(data, salt, nonce []byte, passphrase string) ([]byte, error) {
    key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("failed to create GCM: %v", err)
    }

    if len(data) < gcm.NonceSize() {
        return nil, fmt.Errorf("invalid encrypted data")
    }

    decryptedData, err := gcm.Open(nil, nonce, data[gcm.NonceSize():], nil)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt data: %v", err)
    }

    return decryptedData, nil
}
