package vetting

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
	"github.com/gorilla/mux"
)

// DueDiligenceReport represents a due diligence report for a project.
type DueDiligenceReport struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"project_id"`
	ReviewerID  string    `json:"reviewer_id"`
	Comments    string    `json:"comments"`
	Score       int       `json:"score"`
	CreatedAt   time.Time `json:"created_at"`
}

// DueDiligenceManager manages the due diligence process for projects.
type DueDiligenceManager struct {
	reports map[string]*DueDiligenceReport
	lock    sync.Mutex
}

// NewDueDiligenceManager creates a new instance of DueDiligenceManager.
func NewDueDiligenceManager() *DueDiligenceManager {
	return &DueDiligenceManager{
		reports: make(map[string]*DueDiligenceReport),
	}
}

// AddReport adds a new due diligence report for a project.
func (manager *DueDiligenceManager) AddReport(projectID, reviewerID, comments string, score int) (*DueDiligenceReport, error) {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	id, err := generateUniqueID(projectID + reviewerID)
	if err != nil {
		return nil, err
	}

	report := &DueDiligenceReport{
		ID:         id,
		ProjectID:  projectID,
		ReviewerID: reviewerID,
		Comments:   comments,
		Score:      score,
		CreatedAt:  time.Now(),
	}

	manager.reports[id] = report
	return report, nil
}

// GetReport retrieves a due diligence report by its ID.
func (manager *DueDiligenceManager) GetReport(id string) (*DueDiligenceReport, error) {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	report, exists := manager.reports[id]
	if !exists {
		return nil, errors.New("report not found")
	}
	return report, nil
}

// ListReports lists all due diligence reports for a given project.
func (manager *DueDiligenceManager) ListReports(projectID string) ([]*DueDiligenceReport, error) {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	var reports []*DueDiligenceReport
	for _, report := range manager.reports {
		if report.ProjectID == projectID {
			reports = append(reports, report)
		}
	}
	return reports, nil
}

// generateUniqueID generates a unique ID using scrypt.
func generateUniqueID(input string) (string, error) {
	salt, err := generateSalt()
	if err != nil {
		return "", err
	}
	dk, err := scrypt.Key([]byte(input), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(dk)
	return hex.EncodeToString(hash[:]), nil
}

// generateSalt generates a salt for hashing.
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

// APIHandler handles HTTP requests for due diligence reports.
type APIHandler struct {
	manager *DueDiligenceManager
}

// NewAPIHandler creates a new APIHandler.
func NewAPIHandler(manager *DueDiligenceManager) *APIHandler {
	return &APIHandler{manager: manager}
}

// AddReportHandler handles adding new due diligence reports.
func (handler *APIHandler) AddReportHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ProjectID string `json:"project_id"`
		ReviewerID string `json:"reviewer_id"`
		Comments  string `json:"comments"`
		Score     int    `json:"score"`
	}
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newReport, err := handler.manager.AddReport(request.ProjectID, request.ReviewerID, request.Comments, request.Score)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newReport)
}

// GetReportHandler handles retrieving a due diligence report.
func (handler *APIHandler) GetReportHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	report, err := handler.manager.GetReport(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

// ListReportsHandler handles listing all due diligence reports for a project.
func (handler *APIHandler) ListReportsHandler(w http.ResponseWriter, r *http.Request) {
	projectID := mux.Vars(r)["project_id"]
	reports, err := handler.manager.ListReports(projectID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reports)
}

// SetupRouter sets up the HTTP router.
func SetupRouter(handler *APIHandler) *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/due_diligence_reports", handler.AddReportHandler).Methods("POST")
	r.HandleFunc("/due_diligence_reports/{id}", handler.GetReportHandler).Methods("GET")
	r.HandleFunc("/due_diligence_reports/project/{project_id}", handler.ListReportsHandler).Methods("GET")
	return r
}

// Encryption and decryption utilities for additional security.
func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func createHash(key string) string {
	hash := sha256.New()
	hash.Write([]byte(key))
	return hex.EncodeToString(hash.Sum(nil))
}
