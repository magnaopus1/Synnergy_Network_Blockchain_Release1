package launchpad

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
    "net/http"
    "sync"
    "time"

    "github.com/gorilla/mux"
    "golang.org/x/crypto/scrypt"
)

// MarketingService represents a comprehensive marketing and PR service
type MarketingService struct {
    ID            string    `json:"id"`
    Name          string    `json:"name"`
    Description   string    `json:"description"`
    Creator       string    `json:"creator"`
    CreatedAt     time.Time `json:"created_at"`
    PRDetails     string    `json:"pr_details"`
    Campaigns     []string  `json:"campaigns"`
    EncryptedData string    `json:"encrypted_data"`
}

// MarketingServiceRequest represents a request for creating a marketing service
type MarketingServiceRequest struct {
    Name        string `json:"name"`
    Description string `json:"description"`
    Creator     string `json:"creator"`
    PRDetails   string `json:"pr_details"`
}

// MarketingServiceManager manages comprehensive marketing and PR services
type MarketingServiceManager struct {
    Services map[string]*MarketingService
    Lock     sync.Mutex
}

// NewMarketingServiceManager creates a new MarketingServiceManager instance
func NewMarketingServiceManager() *MarketingServiceManager {
    return &MarketingServiceManager{
        Services: make(map[string]*MarketingService),
    }
}

// CreateMarketingService creates a new marketing service
func (manager *MarketingServiceManager) CreateMarketingService(request MarketingServiceRequest) (*MarketingService, error) {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    id, err := generateUniqueID(request.Creator + time.Now().String())
    if err != nil {
        return nil, err
    }

    encryptedData, err := encryptPRDetails(request.PRDetails, id)
    if err != nil {
        return nil, err
    }

    service := &MarketingService{
        ID:            id,
        Name:          request.Name,
        Description:   request.Description,
        Creator:       request.Creator,
        CreatedAt:     time.Now(),
        PRDetails:     request.PRDetails,
        Campaigns:     []string{},
        EncryptedData: encryptedData,
    }

    manager.Services[id] = service
    return service, nil
}

// GetMarketingService retrieves a marketing service by ID
func (manager *MarketingServiceManager) GetMarketingService(id string) (*MarketingService, error) {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    service, exists := manager.Services[id]
    if !exists {
        return nil, errors.New("service not found")
    }
    return service, nil
}

// ListMarketingServices lists all marketing services
func (manager *MarketingServiceManager) ListMarketingServices() []*MarketingService {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    services := make([]*MarketingService, 0, len(manager.Services))
    for _, service := range manager.Services {
        services = append(services, service)
    }
    return services
}

// AddCampaign adds a campaign to the marketing service
func (manager *MarketingServiceManager) AddCampaign(id, campaign string) error {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    service, exists := manager.Services[id]
    if !exists {
        return errors.New("service not found")
    }

    service.Campaigns = append(service.Campaigns, campaign)
    return nil
}

// generateUniqueID generates a unique ID using scrypt
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

// generateSalt generates a salt for hashing
func generateSalt() ([]byte, error) {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    return salt, err
}

// encryptPRDetails encrypts PR details using AES
func encryptPRDetails(details, key string) (string, error) {
    block, err := aes.NewCipher([]byte(createHash(key)))
    if err != nil {
        return "", err
    }

    plaintext := []byte(details)
    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

    return hex.EncodeToString(ciphertext), nil
}

// createHash creates a SHA-256 hash of the key
func createHash(key string) string {
    hash := sha256.Sum256([]byte(key))
    return hex.EncodeToString(hash[:])
}

// APIHandler handles HTTP requests for marketing services
type APIHandler struct {
    manager *MarketingServiceManager
}

// NewAPIHandler creates a new APIHandler
func NewAPIHandler(manager *MarketingServiceManager) *APIHandler {
    return &APIHandler{manager: manager}
}

// CreateMarketingServiceHandler handles creating marketing services
func (handler *APIHandler) CreateMarketingServiceHandler(w http.ResponseWriter, r *http.Request) {
    var request MarketingServiceRequest
    err := json.NewDecoder(r.Body).Decode(&request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    newService, err := handler.manager.CreateMarketingService(request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(newService)
}

// GetMarketingServiceHandler handles retrieving a marketing service
func (handler *APIHandler) GetMarketingServiceHandler(w http.ResponseWriter, r *http.Request) {
    id := mux.Vars(r)["id"]
    service, err := handler.manager.GetMarketingService(id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(service)
}

// ListMarketingServicesHandler handles listing all marketing services
func (handler *APIHandler) ListMarketingServicesHandler(w http.ResponseWriter, r *http.Request) {
    services := handler.manager.ListMarketingServices()
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(services)
}

// AddCampaignHandler handles adding campaigns to marketing services
func (handler *APIHandler) AddCampaignHandler(w http.ResponseWriter, r *http.Request) {
    id := mux.Vars(r)["id"]
    var request struct {
        Campaign string `json:"campaign"`
    }
    err := json.NewDecoder(r.Body).Decode(&request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    err = handler.manager.AddCampaign(id, request.Campaign)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

// SetupRouter sets up the HTTP router
func SetupRouter(handler *APIHandler) *mux.Router {
    r := mux.NewRouter()
    r.HandleFunc("/marketing_service", handler.CreateMarketingServiceHandler).Methods("POST")
    r.HandleFunc("/marketing_service/{id}", handler.GetMarketingServiceHandler).Methods("GET")
    r.HandleFunc("/marketing_services", handler.ListMarketingServicesHandler).Methods("GET")
    r.HandleFunc("/marketing_service/{id}/campaign", handler.AddCampaignHandler).Methods("POST")
    return r
}

// main initializes and starts the server
func main() {
    manager := NewMarketingServiceManager()
    handler := NewAPIHandler(manager)
    router := SetupRouter(handler)

    fmt.Println("Server started at :8080")
    http.ListenAndServe(":8080", router)
}
