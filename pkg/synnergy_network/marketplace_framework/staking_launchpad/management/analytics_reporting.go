package management

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

    "github.com/gorilla/mux"
    "golang.org/x/crypto/scrypt"
    "net/http"
)

// AnalyticsReport represents an analytics report in the staking launchpad.
type AnalyticsReport struct {
    ID          string    `json:"id"`
    Title       string    `json:"title"`
    Description string    `json:"description"`
    Creator     string    `json:"creator"`
    CreatedAt   time.Time `json:"created_at"`
    Data        string    `json:"data"`
    EncryptedData string  `json:"encrypted_data"`
}

// AnalyticsReportRequest represents a request for creating an analytics report.
type AnalyticsReportRequest struct {
    Title       string `json:"title"`
    Description string `json:"description"`
    Creator     string `json:"creator"`
    Data        string `json:"data"`
}

// AnalyticsReportManager manages the creation and retrieval of analytics reports.
type AnalyticsReportManager struct {
    Reports map[string]*AnalyticsReport
    Lock    sync.Mutex
}

// NewAnalyticsReportManager creates a new instance of AnalyticsReportManager.
func NewAnalyticsReportManager() *AnalyticsReportManager {
    return &AnalyticsReportManager{
        Reports: make(map[string]*AnalyticsReport),
    }
}

// CreateAnalyticsReport creates a new analytics report.
func (manager *AnalyticsReportManager) CreateAnalyticsReport(request AnalyticsReportRequest) (*AnalyticsReport, error) {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    id, err := generateUniqueID(request.Creator + time.Now().String())
    if err != nil {
        return nil, err
    }

    encryptedData, err := encryptData(request.Data, id)
    if err != nil {
        return nil, err
    }

    report := &AnalyticsReport{
        ID:           id,
        Title:        request.Title,
        Description:  request.Description,
        Creator:      request.Creator,
        CreatedAt:    time.Now(),
        Data:         request.Data,
        EncryptedData: encryptedData,
    }

    manager.Reports[id] = report
    return report, nil
}

// GetAnalyticsReport retrieves an analytics report by ID.
func (manager *AnalyticsReportManager) GetAnalyticsReport(id string) (*AnalyticsReport, error) {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    report, exists := manager.Reports[id]
    if !exists {
        return nil, errors.New("report not found")
    }
    return report, nil
}

// ListAnalyticsReports lists all analytics reports.
func (manager *AnalyticsReportManager) ListAnalyticsReports() []*AnalyticsReport {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    reports := make([]*AnalyticsReport, 0, len(manager.Reports))
    for _, report := range manager.Reports {
        reports = append(reports, report)
    }
    return reports
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

// encryptData encrypts the data using AES.
func encryptData(data, key string) (string, error) {
    block, err := aes.NewCipher([]byte(createHash(key)))
    if err != nil {
        return "", err
    }

    plaintext := []byte(data)
    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

    return hex.EncodeToString(ciphertext), nil
}

// createHash creates a SHA-256 hash of the key.
func createHash(key string) string {
    hash := sha256.Sum256([]byte(key))
    return hex.EncodeToString(hash[:])
}

// APIHandler handles HTTP requests for analytics reports.
type APIHandler struct {
    manager *AnalyticsReportManager
}

// NewAPIHandler creates a new APIHandler.
func NewAPIHandler(manager *AnalyticsReportManager) *APIHandler {
    return &APIHandler{manager: manager}
}

// CreateAnalyticsReportHandler handles creating analytics reports.
func (handler *APIHandler) CreateAnalyticsReportHandler(w http.ResponseWriter, r *http.Request) {
    var request AnalyticsReportRequest
    err := json.NewDecoder(r.Body).Decode(&request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    newReport, err := handler.manager.CreateAnalyticsReport(request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(newReport)
}

// GetAnalyticsReportHandler handles retrieving an analytics report.
func (handler *APIHandler) GetAnalyticsReportHandler(w http.ResponseWriter, r *http.Request) {
    id := mux.Vars(r)["id"]
    report, err := handler.manager.GetAnalyticsReport(id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(report)
}

// ListAnalyticsReportsHandler handles listing all analytics reports.
func (handler *APIHandler) ListAnalyticsReportsHandler(w http.ResponseWriter, r *http.Request) {
    reports := handler.manager.ListAnalyticsReports()
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(reports)
}

// SetupRouter sets up the HTTP router.
func SetupRouter(handler *APIHandler) *mux.Router {
    r := mux.NewRouter()
    r.HandleFunc("/analytics_report", handler.CreateAnalyticsReportHandler).Methods("POST")
    r.HandleFunc("/analytics_report/{id}", handler.GetAnalyticsReportHandler).Methods("GET")
    r.HandleFunc("/analytics_reports", handler.ListAnalyticsReportsHandler).Methods("GET")
    return r
}

// main initializes and starts the server.
func main() {
    manager := NewAnalyticsReportManager()
    handler := NewAPIHandler(manager)
    router := SetupRouter(handler)

    fmt.Println("Server started at :8080")
    http.ListenAndServe(":8080", router)
}
