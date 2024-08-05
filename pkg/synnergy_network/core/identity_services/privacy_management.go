package privacy_management

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/identity_services/personal_data_vaults/encrypted_storage"
)


// NewAuditTrailManager creates a new instance of AuditTrailManager
func NewAuditTrailManager() *AuditTrailManager {
	return &AuditTrailManager{
		trails: make(map[string]*AuditTrail),
	}
}

// CreateAuditTrail creates a new audit trail
func (atm *AuditTrailManager) CreateAuditTrail(event string, data interface{}, verifier string) (*AuditTrail, error) {
	atm.mu.Lock()
	defer atm.mu.Unlock()

	// Serialize data to JSON
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// Hash the data
	hash := sha256.Sum256(dataBytes)
	dataHash := hex.EncodeToString(hash[:])

	// Generate a unique ID for the audit trail
	trailID := generateAuditTrailID()

	// Create the audit trail
	auditTrail := &AuditTrail{
		ID:        trailID,
		Event:     event,
		Timestamp: time.Now(),
		DataHash:  dataHash,
		Verifier:  verifier,
	}

	// Sign the audit trail
	signature, err := signData(dataHash, verifier)
	if err != nil {
		return nil, err
	}
	auditTrail.Signature = signature

	// Store the audit trail
	atm.trails[trailID] = auditTrail

	return auditTrail, nil
}

// VerifyAuditTrail verifies the integrity and authenticity of an audit trail
func (atm *AuditTrailManager) VerifyAuditTrail(trailID string) (bool, error) {
	atm.mu.Lock()
	defer atm.mu.Unlock()

	auditTrail, exists := atm.trails[trailID]
	if !exists {
		return false, errors.New("audit trail not found")
	}

	// Verify the signature
	valid, err := verifySignature(auditTrail.DataHash, auditTrail.Signature, auditTrail.Verifier)
	if err != nil || !valid {
		return false, err
	}

	return true, nil
}

// Generate a unique ID for an audit trail
func generateAuditTrailID() string {
	hash := sha256.Sum256([]byte(time.Now().String()))
	return hex.EncodeToString(hash[:])
}

// Sign the data using the verifier's private key
func signData(dataHash, verifier string) (string, error) {
	// Implement signing logic using the verifier's private key
	// Placeholder for signing process
	signature := fmt.Sprintf("signed_%s", dataHash)
	return signature, nil
}

// Verify the signature using the verifier's public key
func verifySignature(dataHash, signature, verifier string) (bool, error) {
	// Implement signature verification logic using the verifier's public key
	// Placeholder for verification process
	expectedSignature := fmt.Sprintf("signed_%s", dataHash)
	return signature == expectedSignature, nil
}

// SerializeAuditTrail serializes an audit trail to JSON
func SerializeAuditTrail(auditTrail *AuditTrail) (string, error) {
	data, err := json.Marshal(auditTrail)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// DeserializeAuditTrail deserializes a JSON string to an audit trail object
func DeserializeAuditTrail(data string) (*AuditTrail, error) {
	var auditTrail AuditTrail
	err := json.Unmarshal([]byte(data), &auditTrail)
	if err != nil {
		return nil, err
	}
	return &auditTrail, nil
}

// StoreAuditTrail stores an audit trail in encrypted storage
func (atm *AuditTrailManager) StoreAuditTrail(auditTrail *AuditTrail) error {
	auditTrailData, err := SerializeAuditTrail(auditTrail)
	if err != nil {
		return err
	}

	// Encrypt the audit trail data
	encryptedData, err := encrypted_storage.EncryptData([]byte(auditTrailData))
	if err != nil {
		return err
	}

	// Store the encrypted data
	err = encrypted_storage.StoreData(auditTrail.ID, encryptedData)
	if err != nil {
		return err
	}

	return nil
}

// RetrieveAuditTrail retrieves an audit trail from encrypted storage
func (atm *AuditTrailManager) RetrieveAuditTrail(trailID string) (*AuditTrail, error) {
	// Retrieve the encrypted data
	encryptedData, err := encrypted_storage.RetrieveData(trailID)
	if err != nil {
		return nil, err
	}

	// Decrypt the data
	decryptedData, err := encrypted_storage.DecryptData(encryptedData)
	if err != nil {
		return nil, err
	}

	// Deserialize the audit trail
	auditTrail, err := DeserializeAuditTrail(string(decryptedData))
	if err != nil {
		return nil, err
	}

	return auditTrail, nil
}

// NewComplianceManager initializes a new ComplianceManager
func NewComplianceManager() *ComplianceManager {
	return &ComplianceManager{
		complianceRules: make(map[string]ComplianceRule),
		encryptedLogs:   make(map[string]string),
	}
}

// AddComplianceRule adds a new compliance rule
func (cm *ComplianceManager) AddComplianceRule(rule ComplianceRule) {
	cm.complianceRules[rule.ID] = rule
}

// CheckCompliance checks if an action complies with all rules
func (cm *ComplianceManager) CheckCompliance(action string, data map[string]string) (bool, []string) {
	var nonCompliantRules []string
	for _, rule := range cm.complianceRules {
		if contains(rule.AppliesTo, action) {
			for _, condition := range rule.Conditions {
				if !evaluateCondition(condition, data) {
					nonCompliantRules = append(nonCompliantRules, rule.ID)
				}
			}
		}
	}
	return len(nonCompliantRules) == 0, nonCompliantRules
}

// LogComplianceAction logs an action in compliance with rules
func (cm *ComplianceManager) LogComplianceAction(action string, data map[string]string, encryptionKey string) error {
	logEntry := createLogEntry(action, data)
	encryptedLog, err := encryptLogEntry(logEntry, encryptionKey)
	if err != nil {
		return err
	}
	timestamp := time.Now().Format(time.RFC3339)
	cm.encryptedLogs[timestamp] = encryptedLog
	return nil
}

// GetComplianceLog retrieves the compliance log entry for a specific timestamp
func (cm *ComplianceManager) GetComplianceLog(timestamp, encryptionKey string) (string, error) {
	encryptedLog, exists := cm.encryptedLogs[timestamp]
	if !exists {
		return "", errors.New("log entry not found")
	}
	decryptedLog, err := decryptLogEntry(encryptedLog, encryptionKey)
	if err != nil {
		return "", err
	}
	return decryptedLog, nil
}

// Helper functions

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// evaluateCondition evaluates a compliance condition based on data
func evaluateCondition(condition string, data map[string]string) bool {
	// Implement condition evaluation logic here
	// This is a placeholder function
	return true
}

// createLogEntry creates a log entry string from action and data
func createLogEntry(action string, data map[string]string) string {
	// Implement log entry creation logic here
	// This is a placeholder function
	return action
}

// encryptLogEntry encrypts a log entry using AES
func encryptLogEntry(logEntry, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
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
	ciphertext := gcm.Seal(nonce, nonce, []byte(logEntry), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptLogEntry decrypts a log entry using AES
func decryptLogEntry(encryptedLog, key string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedLog)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}


// GenerateKey derives a key from a password using Scrypt and HKDF
func GenerateKey(password, salt []byte) ([]byte, error) {
	const KeyLength = 32

	// Derive key using Scrypt
	scryptKey, err := scrypt.Key(password, salt, 1<<14, 8, 1, KeyLength)
	if err != nil {
		return nil, err
	}

	// Further derive key using HKDF
	hash := sha256.New
	hkdf := hkdf.New(hash, scryptKey, salt, nil)
	key := make([]byte, KeyLength)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}

	return key, nil
}

// Encryption and Decryption using AES-GCM

// Encrypt encrypts plaintext using AES-GCM with the given key and returns the ciphertext and nonce
func Encrypt(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext using AES-GCM with the given key and nonce
func Decrypt(ciphertext, key, nonce []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Homomorphic Encryption Placeholder (for demonstration, real implementation requires a dedicated library)

// HomomorphicEncrypt performs a dummy homomorphic encryption
func HomomorphicEncrypt(plaintext int64) (ciphertext *big.Int) {
	// Placeholder: Replace with a real homomorphic encryption algorithm
	return big.NewInt(plaintext)
}

// HomomorphicAdd performs a dummy homomorphic addition
func HomomorphicAdd(ciphertext1, ciphertext2 *big.Int) *big.Int {
	// Placeholder: Replace with a real homomorphic addition algorithm
	return new(big.Int).Add(ciphertext1, ciphertext2)
}

// Secure Multiparty Computation Placeholder (for demonstration, real implementation requires a dedicated library)

// SecureCompute performs a dummy secure multiparty computation
func SecureCompute(inputs ...int64) (result int64) {
	// Placeholder: Replace with a real secure multiparty computation algorithm
	sum := int64(0)
	for _, input := range inputs {
		sum += input
	}
	return sum
}

// Differential Privacy using Laplace Mechanism

// LaplaceNoise generates Laplace noise for differential privacy
func LaplaceNoise(scale float64) float64 {
	// Placeholder: Replace with a real Laplace noise generator
	// Use a simplified method to generate Laplace noise
	u := rand.Float64() - 0.5
	return scale * sign(u) * math.Log(1-2*math.Abs(u))
}

// sign returns the sign of a float64 number
func sign(x float64) float64 {
	if x < 0 {
		return -1
	}
	return 1
}

// AddNoise adds Laplace noise to a value for differential privacy
func AddNoise(value int64, scale float64) float64 {
	noise := LaplaceNoise(scale)
	return float64(value) + noise
}


// NewAggregator initializes a new Aggregator instance
func NewAggregator(noiseLevel float64) *Aggregator {
	return &Aggregator{
		Data:       make([]string, 0),
		Keys:       make(map[string]string),
		NoiseLevel: noiseLevel,
	}
}

// AddData adds encrypted data to the aggregator
func (a *Aggregator) AddData(data string, key string) {
	encryptedData := encryptData(data, key)
	a.Data = append(a.Data, encryptedData)
	a.Keys[encryptedData] = key
}

// encryptData encrypts the given data using AES encryption
func encryptData(data string, key string) string {
	block, err := aes.NewCipher([]byte(createHash(key)))
	if err != nil {
		panic(err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		panic(err.Error())
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext)
}

// createHash generates a SHA-256 hash for the given key
func createHash(key string) string {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

// AggregateData performs privacy-preserving data aggregation
func (a *Aggregator) AggregateData() string {
	aggregatedResult := ""

	for _, encryptedData := range a.Data {
		decryptedData := decryptData(encryptedData, a.Keys[encryptedData])
		aggregatedResult += decryptedData + " "
	}

	// Apply differential privacy
	aggregatedResult = addDifferentialPrivacy(aggregatedResult, a.NoiseLevel)

	return aggregatedResult
}

// decryptData decrypts the given encrypted data using AES decryption
func decryptData(encryptedData string, key string) string {
	data, _ := hex.DecodeString(encryptedData)
	block, err := aes.NewCipher([]byte(createHash(key)))
	if err != nil {
		panic(err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error()))
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return string(plaintext)
}

// addDifferentialPrivacy adds noise to the data to ensure differential privacy
func addDifferentialPrivacy(data string, noiseLevel float64) string {
	// Convert the data to a numeric value for simplicity
	dataValue, err := strconv.ParseFloat(data, 64)
	if err != nil {
		panic(err.Error())
	}

	// Generate Laplacian noise
	noise := generateLaplacianNoise(noiseLevel)
	noisyData := dataValue + noise

	return strconv.FormatFloat(noisyData, 'f', 6, 64)
}

// generateLaplacianNoise generates Laplacian noise for differential privacy
func generateLaplacianNoise(scale float64) float64 {
	// Laplace distribution can be generated using inverse transform sampling
	u := rand.Float64() - 0.5
	return scale * sign(u) * math.Log(1-2*math.Abs(u))
}

// sign function to return the sign of a float
func sign(x float64) float64 {
	if x < 0 {
		return -1
	}
	return 1
}

// FederatedLearning handles federated learning operations
type FederatedLearning struct {
	Participants []string
	Updates      []string
}

// NewFederatedLearning initializes a new FederatedLearning instance
func NewFederatedLearning() *FederatedLearning {
	return &FederatedLearning{
		Participants: make([]string, 0),
		Updates:      make([]string, 0),
	}
}

// AddParticipant adds a new participant to the federated learning process
func (fl *FederatedLearning) AddParticipant(participant string) {
	fl.Participants = append(fl.Participants, participant)
}

// AddUpdate adds a new model update from a participant
func (fl *FederatedLearning) AddUpdate(update string) {
	fl.Updates = append(fl.Updates, update)
}

// AggregateUpdates aggregates the model updates using secure multi-party computation (SMC)
func (fl *FederatedLearning) AggregateUpdates() string {
	aggregatedModel := ""

	for _, update := range fl.Updates {
		aggregatedModel += update + " "
	}

	// Apply secure multi-party computation (SMC) techniques
	aggregatedModel = cryptographic_techniques.SecureMultiPartyComputation(aggregatedModel)

	return aggregatedModel
}


// GenerateNoise generates Laplacian noise
func (lng *LaplaceNoiseGenerator) GenerateNoise() float64 {
	u := rand.Float64() - 0.5
	return lng.Sensitivity / lng.Epsilon * sign(u) * math.Log(1-2*math.Abs(u))
}

// sign function to return the sign of a float
func sign(x float64) float64 {
	if x < 0 {
		return -1
	}
	return 1
}

// NewDifferentialPrivacyManager initializes a new DifferentialPrivacyManager instance
func NewDifferentialPrivacyManager(epsilon, delta, privacyBudget float64, noiseGenerator NoiseGenerator) *DifferentialPrivacyManager {
	return &DifferentialPrivacyManager{
		Epsilon:       epsilon,
		Delta:         delta,
		PrivacyBudget: privacyBudget,
		NoiseGenerator: noiseGenerator,
	}
}

// ApplyDifferentialPrivacy adds differential privacy to the data
func (dpm *DifferentialPrivacyManager) ApplyDifferentialPrivacy(data float64) float64 {
	noise := dpm.NoiseGenerator.GenerateNoise()
	return data + noise
}

// UpdatePrivacyBudget updates the privacy budget after a query
func (dpm *DifferentialPrivacyManager) UpdatePrivacyBudget() {
	dpm.PrivacyBudget -= dpm.Epsilon
	if dpm.PrivacyBudget < 0 {
		dpm.PrivacyBudget = 0
	}
}

// CheckPrivacyBudget checks if the privacy budget is exhausted
func (dpm *DifferentialPrivacyManager) CheckPrivacyBudget() bool {
	return dpm.PrivacyBudget > 0
}

// EncryptData uses Scrypt for key derivation and AES for encryption
func EncryptData(data string, passphrase string) (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData uses Scrypt for key derivation and AES for decryption
func DecryptData(ciphertext string, passphrase string) (string, error) {
	data, _ := hex.DecodeString(ciphertext)
	salt := data[:16]
	ciphertext = data[16:]

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}


// NewDifferentialPrivacyPolicy initializes a new DifferentialPrivacyPolicy instance
func NewDifferentialPrivacyPolicy(epsilon, delta float64, maxQueries int) *DifferentialPrivacyPolicy {
	return &DifferentialPrivacyPolicy{
		Epsilon:    epsilon,
		Delta:      delta,
		MaxQueries: maxQueries,
		StartTime:  time.Now(),
	}
}

// CanQuery checks if a query can be made under the current policy
func (dpp *DifferentialPrivacyPolicy) CanQuery() bool {
	if dpp.QueryCount >= dpp.MaxQueries {
		return false
	}
	return true
}

// RegisterQuery registers a query under the current policy
func (dpp *DifferentialPrivacyPolicy) RegisterQuery() {
	dpp.QueryCount++
}

func main() {
	// Example Usage
	noiseGen := &LaplaceNoiseGenerator{Sensitivity: 1.0, Epsilon: 0.1}
	dpm := NewDifferentialPrivacyManager(0.1, 0.01, 1.0, noiseGen)
	data := 100.0
	privacyData := dpm.ApplyDifferentialPrivacy(data)
	println(privacyData)
}


// NewFederatedLearningManager initializes a new FederatedLearningManager instance
func NewFederatedLearningManager() *FederatedLearningManager {
	return &FederatedLearningManager{
		Participants:        make(map[string]*Participant),
		ModelUpdates:        make(map[string]string),
		ModelUpdateChannels: make(map[string]chan string),
	}
}

// RegisterParticipant registers a new participant in the federated learning process
func (flm *FederatedLearningManager) RegisterParticipant(participantID, localModel string) {
	flm.Mutex.Lock()
	defer flm.Mutex.Unlock()
	flm.Participants[participantID] = &Participant{
		ID:           participantID,
		LocalModel:   localModel,
		UpdateStatus: false,
	}
	flm.ModelUpdateChannels[participantID] = make(chan string)
}

// SubmitModelUpdate allows a participant to submit their model update
func (flm *FederatedLearningManager) SubmitModelUpdate(participantID, modelUpdate string) error {
	flm.Mutex.Lock()
	defer flm.Mutex.Unlock()

	participant, exists := flm.Participants[participantID]
	if !exists {
		return errors.New("participant not found")
	}

	flm.ModelUpdates[participantID] = modelUpdate
	participant.UpdateStatus = true
	flm.ModelUpdateChannels[participantID] <- modelUpdate

	return nil
}

// AggregateModelUpdates aggregates the model updates from all participants
func (flm *FederatedLearningManager) AggregateModelUpdates() (string, error) {
	flm.Mutex.Lock()
	defer flm.Mutex.Unlock()

	aggregatedModel := ""
	for _, update := range flm.ModelUpdates {
		aggregatedModel += update + " "
	}

	// Encrypt the aggregated model
	encryptedModel, err := encryptData(aggregatedModel, "global_model_key")
	if err != nil {
		return "", err
	}

	flm.GlobalModel = encryptedModel

	// Reset update status
	for _, participant := range flm.Participants {
		participant.UpdateStatus = false
	}

	return encryptedModel, nil
}

// encryptData encrypts the given data using AES encryption
func encryptData(data string, passphrase string) (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// decryptData decrypts the given encrypted data using AES decryption
func decryptData(encryptedData, passphrase string) (string, error) {
	data, _ := hex.DecodeString(encryptedData)
	salt := data[:16]
	ciphertext := data[16:]

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// WaitForModelUpdates waits for model updates from all participants
func (flm *FederatedLearningManager) WaitForModelUpdates() {
	var wg sync.WaitGroup

	for participantID, ch := range flm.ModelUpdateChannels {
		wg.Add(1)
		go func(pid string, c chan string) {
			defer wg.Done()
			select {
			case update := <-c:
				fmt.Printf("Received update from %s: %s\n", pid, update)
			}
		}(participantID, ch)
	}

	wg.Wait()
}

// VerifyModelUpdate verifies the integrity of the model update
func (flm *FederatedLearningManager) VerifyModelUpdate(participantID, modelUpdate string) bool {
	hash := sha256.Sum256([]byte(modelUpdate))
	return hex.EncodeToString(hash[:]) == modelUpdate
}

// ApplySecureAggregation applies secure aggregation techniques to the model updates
func (flm *FederatedLearningManager) ApplySecureAggregation() (string, error) {
	flm.Mutex.Lock()
	defer flm.Mutex.Unlock()

	aggregatedModel := ""

	for participantID, update := range flm.ModelUpdates {
		if flm.VerifyModelUpdate(participantID, update) {
			aggregatedModel += update + " "
		} else {
			return "", errors.New("model update verification failed")
		}
	}

	encryptedModel, err := encryptData(aggregatedModel, "global_model_key")
	if err != nil {
		return "", err
	}

	flm.GlobalModel = encryptedModel
	return encryptedModel, nil
}

// NewHomomorphicEncryptionManager initializes a new HomomorphicEncryptionManager instance
func NewHomomorphicEncryptionManager(publicKey *cryptographic_techniques.PublicKey, privateKey *cryptographic_techniques.PrivateKey) *HomomorphicEncryptionManager {
	return &HomomorphicEncryptionManager{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}
}

// Encrypt encrypts data using the homomorphic encryption public key
func (hem *HomomorphicEncryptionManager) Encrypt(data *big.Int) (*cryptographic_techniques.Ciphertext, error) {
	if hem.PublicKey == nil {
		return nil, errors.New("public key is not initialized")
	}
	return cryptographic_techniques.Encrypt(hem.PublicKey, data)
}

// Decrypt decrypts data using the homomorphic encryption private key
func (hem *HomomorphicEncryptionManager) Decrypt(ciphertext *cryptographic_techniques.Ciphertext) (*big.Int, error) {
	if hem.PrivateKey == nil {
		return nil, errors.New("private key is not initialized")
	}
	return cryptographic_techniques.Decrypt(hem.PrivateKey, ciphertext)
}

// AddCiphertexts adds two ciphertexts homomorphically
func (hem *HomomorphicEncryptionManager) AddCiphertexts(ciphertext1, ciphertext2 *cryptographic_techniques.Ciphertext) (*cryptographic_techniques.Ciphertext, error) {
	return cryptographic_techniques.AddCiphertexts(hem.PublicKey, ciphertext1, ciphertext2)
}

// MultiplyCiphertextByConstant multiplies a ciphertext by a constant homomorphically
func (hem *HomomorphicEncryptionManager) MultiplyCiphertextByConstant(ciphertext *cryptographic_techniques.Ciphertext, constant *big.Int) (*cryptographic_techniques.Ciphertext, error) {
	return cryptographic_techniques.MultiplyCiphertextByConstant(hem.PublicKey, ciphertext, constant)
}

// SecureAggregationManager manages secure aggregation using homomorphic encryption
type SecureAggregationManager struct {
	HEManager *HomomorphicEncryptionManager
}

// NewSecureAggregationManager initializes a new SecureAggregationManager instance
func NewSecureAggregationManager(heManager *HomomorphicEncryptionManager) *SecureAggregationManager {
	return &SecureAggregationManager{
		HEManager: heManager,
	}
}

// Aggregate encrypts and aggregates data securely
func (sam *SecureAggregationManager) Aggregate(data []*big.Int) (*cryptographic_techniques.Ciphertext, error) {
	var aggregatedCiphertext *cryptographic_techniques.Ciphertext
	for _, value := range data {
		encryptedValue, err := sam.HEManager.Encrypt(value)
		if err != nil {
			return nil, err
		}
		if aggregatedCiphertext == nil {
			aggregatedCiphertext = encryptedValue
		} else {
			aggregatedCiphertext, err = sam.HEManager.AddCiphertexts(aggregatedCiphertext, encryptedValue)
			if err != nil {
				return nil, err
			}
		}
	}
	return aggregatedCiphertext, nil
}

// DecryptAggregatedData decrypts the aggregated ciphertext
func (sam *SecureAggregationManager) DecryptAggregatedData(aggregatedCiphertext *cryptographic_techniques.Ciphertext) (*big.Int, error) {
	return sam.HEManager.Decrypt(aggregatedCiphertext)
}

// UseCaseExample demonstrates the use of homomorphic encryption in a real-world scenario
func UseCaseExample() {
	// Example data
	data := []*big.Int{
		big.NewInt(100),
		big.NewInt(200),
		big.NewInt(300),
	}

	// Initialize keys (In a real scenario, keys should be securely generated and stored)
	publicKey, privateKey := cryptographic_techniques.GenerateKeyPair()

	// Initialize HomomorphicEncryptionManager
	heManager := NewHomomorphicEncryptionManager(publicKey, privateKey)

	// Initialize SecureAggregationManager
	sam := NewSecureAggregationManager(heManager)

	// Aggregate data securely
	aggregatedCiphertext, err := sam.Aggregate(data)
	if err != nil {
		fmt.Println("Error during aggregation:", err)
		return
	}

	// Decrypt aggregated data
	aggregatedData, err := sam.DecryptAggregatedData(aggregatedCiphertext)
	if err != nil {
		fmt.Println("Error during decryption:", err)
		return
	}

	fmt.Println("Aggregated Data:", aggregatedData)
}

// NewPrivacyManager initializes a new PrivacyManager instance
func NewPrivacyManager() *PrivacyManager {
	return &PrivacyManager{
		AccessControl:      NewAccessControlManager(),
		PrivacyPreferences: make(map[string]*PrivacyPreferences),
	}
}

// NewAccessControlManager initializes a new AccessControlManager instance
func NewAccessControlManager() *AccessControlManager {
	return &AccessControlManager{
		Roles:    make(map[string][]string),
		Policies: make(map[string]AccessPolicy),
	}
}

// AddRole adds a new role with specified permissions
func (acm *AccessControlManager) AddRole(role string, permissions []string) {
	acm.Mutex.Lock()
	defer acm.Mutex.Unlock()
	acm.Roles[role] = permissions
}

// AssignRole assigns a role to a user
func (acm *AccessControlManager) AssignRole(userID string, role string) {
	acm.Mutex.Lock()
	defer acm.Mutex.Unlock()
	acm.Roles[userID] = append(acm.Roles[userID], role)
}

// DefineAccessPolicy defines a new access policy
func (acm *AccessControlManager) DefineAccessPolicy(role string, policy AccessPolicy) {
	acm.Mutex.Lock()
	defer acm.Mutex.Unlock()
	acm.Policies[role] = policy
}

// CheckAccess checks if a user has access to a specific action
func (acm *AccessControlManager) CheckAccess(userID string, action string) bool {
	acm.Mutex.Lock()
	defer acm.Mutex.Unlock()

	roles, exists := acm.Roles[userID]
	if !exists {
		return false
	}

	for _, role := range roles {
		policy, exists := acm.Policies[role]
		if exists && contains(policy.AllowedActions, action) {
			return true
		}
	}
	return false
}

// contains checks if a string is in a slice of strings
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// EncryptData encrypts data using AES encryption
func EncryptData(data string, passphrase string) (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using AES decryption
func DecryptData(ciphertext string, passphrase string) (string, error) {
	data, _ := hex.DecodeString(ciphertext)
	salt := data[:16]
	ciphertext = data[16:]

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// DefinePrivacyPreferences sets privacy preferences for a user
func (pm *PrivacyManager) DefinePrivacyPreferences(userID string, preferences *PrivacyPreferences) {
	pm.Mutex.Lock()
	defer pm.Mutex.Unlock()
	pm.PrivacyPreferences[userID] = preferences
}

// GetPrivacyPreferences retrieves the privacy preferences of a user
func (pm *PrivacyManager) GetPrivacyPreferences(userID string) (*PrivacyPreferences, error) {
	pm.Mutex.Lock()
	defer pm.Mutex.Unlock()
	preferences, exists := pm.PrivacyPreferences[userID]
	if !exists {
		return nil, errors.New("privacy preferences not found")
	}
	return preferences, nil
}

// Example Use Case
func main() {
	// Initialize PrivacyManager
	pm := NewPrivacyManager()

	// Define roles and access policies
	acm := pm.AccessControl
	acm.AddRole("admin", []string{"read", "write", "update", "delete"})
	acm.AddRole("user", []string{"read", "update"})
	acm.DefineAccessPolicy("admin", AccessPolicy{
		Role:           "admin",
		AllowedActions: []string{"read", "write", "update", "delete"},
	})
	acm.DefineAccessPolicy("user", AccessPolicy{
		Role:           "user",
		AllowedActions: []string{"read", "update"},
	})

	// Assign roles to users
	acm.AssignRole("user1", "admin")
	acm.AssignRole("user2", "user")

	// Check access for users
	fmt.Println(acm.CheckAccess("user1", "delete")) // true
	fmt.Println(acm.CheckAccess("user2", "delete")) // false

	// Define and retrieve privacy preferences
	preferences := &PrivacyPreferences{
		UserID: "user1",
		DataAccessPolicies: map[string]AccessPolicy{
			"read": {Role: "user", AllowedActions: []string{"read"}},
		},
		GranularConsent: map[string]bool{
			"share_location": true,
		},
	}
	pm.DefinePrivacyPreferences("user1", preferences)
	userPreferences, err := pm.GetPrivacyPreferences("user1")
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("User Preferences: %+v\n", userPreferences)
	}

	// Encrypt and Decrypt Data
	encryptedData, err := EncryptData("Sensitive Data", "passphrase123")
	if err != nil {
		fmt.Println("Encryption Error:", err)
	} else {
		fmt.Println("Encrypted Data:", encryptedData)
	}

	decryptedData, err := DecryptData(encryptedData, "passphrase123")
	if err != nil {
		fmt.Println("Decryption Error:", err)
	} else {
		fmt.Println("Decrypted Data:", decryptedData)
	}
}

// NewPrivacyPolicyManager initializes a new PrivacyPolicyManager instance
func NewPrivacyPolicyManager() *PrivacyPolicyManager {
	return &PrivacyPolicyManager{
		Policies: make(map[string]*PrivacyPolicy),
	}
}

// CreatePrivacyPolicy creates a new privacy policy for a user
func (ppm *PrivacyPolicyManager) CreatePrivacyPolicy(userID string, rules []PrivacyRule, passphrase string) (*PrivacyPolicy, error) {
	ppm.Mutex.Lock()
	defer ppm.Mutex.Unlock()

	policyID := generatePolicyID()
	policy := &PrivacyPolicy{
		PolicyID: policyID,
		UserID: userID,
		Rules: rules,
	}

	// Encrypt the policy
	encryptedPolicy, encryptionKeyHash, err := encryptPolicy(policy, passphrase)
	if err != nil {
		return nil, err
	}

	policy.EncryptedPolicy = encryptedPolicy
	policy.EncryptionKeyHash = encryptionKeyHash

	ppm.Policies[policyID] = policy
	return policy, nil
}

// encryptPolicy encrypts a privacy policy using AES encryption
func encryptPolicy(policy *PrivacyPolicy, passphrase string) (string, string, error) {
	plaintext, err := json.Marshal(policy)
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

// decryptPolicy decrypts a privacy policy using AES decryption
func decryptPolicy(encryptedPolicy, passphrase, keyHash string) (*PrivacyPolicy, error) {
	data, err := hex.DecodeString(encryptedPolicy)
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

	var policy PrivacyPolicy
	if err := json.Unmarshal(plaintext, &policy); err != nil {
		return nil, err
	}

	return &policy, nil
}

// UpdatePrivacyPolicy updates an existing privacy policy
func (ppm *PrivacyPolicyManager) UpdatePrivacyPolicy(policyID string, rules []PrivacyRule, passphrase string) (*PrivacyPolicy, error) {
	ppm.Mutex.Lock()
	defer ppm.Mutex.Unlock()

	policy, exists := ppm.Policies[policyID]
	if !exists {
		return nil, errors.New("policy not found")
	}

	policy.Rules = rules

	// Encrypt the updated policy
	encryptedPolicy, encryptionKeyHash, err := encryptPolicy(policy, passphrase)
	if err != nil {
		return nil, err
	}

	policy.EncryptedPolicy = encryptedPolicy
	policy.EncryptionKeyHash = encryptionKeyHash

	ppm.Policies[policyID] = policy
	return policy, nil
}

// GetPrivacyPolicy retrieves a privacy policy by its ID
func (ppm *PrivacyPolicyManager) GetPrivacyPolicy(policyID string, passphrase string) (*PrivacyPolicy, error) {
	ppm.Mutex.Lock()
	defer ppm.Mutex.Unlock()

	policy, exists := ppm.Policies[policyID]
	if !exists {
		return nil, errors.New("policy not found")
	}

	// Decrypt the policy
	decryptedPolicy, err := decryptPolicy(policy.EncryptedPolicy, passphrase, policy.EncryptionKeyHash)
	if err != nil {
		return nil, err
	}

	return decryptedPolicy, nil
}

// DeletePrivacyPolicy deletes a privacy policy by its ID
func (ppm *PrivacyPolicyManager) DeletePrivacyPolicy(policyID string) error {
	ppm.Mutex.Lock()
	defer ppm.Mutex.Unlock()

	if _, exists := ppm.Policies[policyID]; !exists {
		return errors.New("policy not found")
	}

	delete(ppm.Policies, policyID)
	return nil
}

// generatePolicyID generates a unique ID for a privacy policy
func generatePolicyID() string {
	// Generate a unique policy ID (e.g., UUID or another unique identifier)
	return "unique-policy-id"
}

// NewAccessControlManager initializes a new AccessControlManager instance
func NewAccessControlManager(ppm *PrivacyPolicyManager) *AccessControlManager {
	return &AccessControlManager{
		PrivacyManager: ppm,
	}
}

// CheckAccess checks if a user has access to a specific data type based on their role and attributes
func (acm *AccessControlManager) CheckAccess(userID, policyID, dataType string, userRole string, userAttributes map[string]string) (bool, error) {
	policy, err := acm.PrivacyManager.GetPrivacyPolicy(policyID, userRole) // Use role as passphrase for simplicity
	if err != nil {
		return false, err
	}

	for _, rule := range policy.Rules {
		if rule.DataType == dataType {
			for _, condition := range rule.AccessConditions {
				if condition.Role == userRole {
					if matchesAttributes(userAttributes, condition.Attributes) {
						return true, nil
					}
				}
			}
		}
	}

	return false, nil
}

// matchesAttributes checks if user attributes match the required attributes
func matchesAttributes(userAttributes, requiredAttributes map[string]string) bool {
	for key, value := range requiredAttributes {
		if userValue, exists := userAttributes[key]; !exists || userValue != value {
			return false
		}
	}
	return true
}

// NewSecureMultipartyComputationManager initializes a new SecureMultipartyComputationManager instance
func NewSecureMultipartyComputationManager() *SecureMultipartyComputationManager {
	return &SecureMultipartyComputationManager{
		GlobalData: make(map[string]*big.Int),
	}
}

// RegisterParticipant registers a new participant in the SMC process
func (smc *SecureMultipartyComputationManager) RegisterParticipant(id string, localData map[string]*big.Int) {
	smc.Mutex.Lock()
	defer smc.Mutex.Unlock()
	participant := &Participant{
		ID:       id,
		LocalData: localData,
	}
	smc.Participants = append(smc.Participants, participant)
}

// ComputeSum computes the sum of all participants' local data for a given key
func (smc *SecureMultipartyComputationManager) ComputeSum(key string) (*big.Int, error) {
	smc.Mutex.Lock()
	defer smc.Mutex.Unlock()

	sum := big.NewInt(0)
	for _, participant := range smc.Participants {
		value, exists := participant.LocalData[key]
		if !exists {
			return nil, errors.New("key not found in participant data")
		}
		sum.Add(sum, value)
	}

	encryptedSum, err := encryptData(sum, "global_sum_key")
	if err != nil {
		return nil, err
	}

	return encryptedSum, nil
}

// ComputeProduct computes the product of all participants' local data for a given key
func (smc *SecureMultipartyComputationManager) ComputeProduct(key string) (*big.Int, error) {
	smc.Mutex.Lock()
	defer smc.Mutex.Unlock()

	product := big.NewInt(1)
	for _, participant := range smc.Participants {
		value, exists := participant.LocalData[key]
		if !exists {
			return nil, errors.New("key not found in participant data")
		}
		product.Mul(product, value)
	}

	encryptedProduct, err := encryptData(product, "global_product_key")
	if err != nil {
		return nil, err
	}

	return encryptedProduct, nil
}

// encryptData encrypts the given data using AES encryption
func encryptData(data *big.Int, passphrase string) (*big.Int, error) {
	dataBytes := data.Bytes()
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, dataBytes, nil)
	return new(big.Int).SetBytes(ciphertext), nil
}

// decryptData decrypts the given encrypted data using AES decryption
func decryptData(encryptedData *big.Int, passphrase string) (*big.Int, error) {
	data := encryptedData.Bytes()
	salt := data[:16]
	ciphertext := data[16:]

	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
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

	return new(big.Int).SetBytes(plaintext), nil
}

