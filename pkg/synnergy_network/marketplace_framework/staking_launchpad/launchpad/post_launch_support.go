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

// PostLaunchService represents a comprehensive post-launch support service
type PostLaunchService struct {
    ID              string    `json:"id"`
    Name            string    `json:"name"`
    Description     string    `json:"description"`
    Creator         string    `json:"creator"`
    CreatedAt       time.Time `json:"created_at"`
    SupportDetails  string    `json:"support_details"`
    EncryptedData   string    `json:"encrypted_data"`
    OngoingServices []string  `json:"ongoing_services"`
}

// PostLaunchServiceRequest represents a request for creating a post-launch service
type PostLaunchServiceRequest struct {
    Name           string `json:"name"`
    Description    string `json:"description"`
    Creator        string `json:"creator"`
    SupportDetails string `json:"support_details"`
}

// PostLaunchServiceManager manages comprehensive post-launch support services
type PostLaunchServiceManager struct {
    Services map[string]*PostLaunchService
    Lock     sync.Mutex
}

// NewPostLaunchServiceManager creates a new PostLaunchServiceManager instance
func NewPostLaunchServiceManager() *PostLaunchServiceManager {
    return &PostLaunchServiceManager{
        Services: make(map[string]*PostLaunchService),
    }
}

// CreatePostLaunchService creates a new post-launch service
func (manager *PostLaunchServiceManager) CreatePostLaunchService(request PostLaunchServiceRequest) (*PostLaunchService, error) {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    id, err := generateUniqueID(request.Creator + time.Now().String())
    if err != nil {
        return nil, err
    }

    encryptedData, err := encryptSupportDetails(request.SupportDetails, id)
    if err != nil {
        return nil, err
    }

    service := &PostLaunchService{
        ID:              id,
        Name:            request.Name,
        Description:     request.Description,
        Creator:         request.Creator,
        CreatedAt:       time.Now(),
        SupportDetails:  request.SupportDetails,
        EncryptedData:   encryptedData,
        OngoingServices: []string{},
    }

    manager.Services[id] = service
    return service, nil
}

// GetPostLaunchService retrieves a post-launch service by ID
func (manager *PostLaunchServiceManager) GetPostLaunchService(id string) (*PostLaunchService, error) {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    service, exists := manager.Services[id]
    if !exists {
        return nil, errors.New("service not found")
    }
    return service, nil
}

// ListPostLaunchServices lists all post-launch services
func (manager *PostLaunchServiceManager) ListPostLaunchServices() []*PostLaunchService {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    services := make([]*PostLaunchService, 0, len(manager.Services))
    for _, service := range manager.Services {
        services = append(services, service)
    }
    return services
}

// AddOngoingService adds an ongoing service to the post-launch service
func (manager *PostLaunchServiceManager) AddOngoingService(id, ongoingService string) error {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    service, exists := manager.Services[id]
    if !exists {
        return errors.New("service not found")
    }

    service.OngoingServices = append(service.OngoingServices, ongoingService)
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

// encryptSupportDetails encrypts support details using AES
func encryptSupportDetails(details, key string) (string, error) {
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

// APIHandler handles HTTP requests for post-launch services
type APIHandler struct {
    manager *PostLaunchServiceManager
}

// NewAPIHandler creates a new APIHandler
func NewAPIHandler(manager *PostLaunchServiceManager) *APIHandler {
    return &APIHandler{manager: manager}
}

// CreatePostLaunchServiceHandler handles creating post-launch services
func (handler *APIHandler) CreatePostLaunchServiceHandler(w http.ResponseWriter, r *http.Request) {
    var request PostLaunchServiceRequest
    err := json.NewDecoder(r.Body).Decode(&request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    newService, err := handler.manager.CreatePostLaunchService(request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(newService)
}

// GetPostLaunchServiceHandler handles retrieving a post-launch service
func (handler *APIHandler) GetPostLaunchServiceHandler(w http.ResponseWriter, r *http.Request) {
    id := mux.Vars(r)["id"]
    service, err := handler.manager.GetPostLaunchService(id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(service)
}

// ListPostLaunchServicesHandler handles listing all post-launch services
func (handler *APIHandler) ListPostLaunchServicesHandler(w http.ResponseWriter, r *http.Request) {
    services := handler.manager.ListPostLaunchServices()
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(services)
}

// AddOngoingServiceHandler handles adding ongoing services to post-launch services
func (handler *APIHandler) AddOngoingServiceHandler(w http.ResponseWriter, r *http.Request) {
    id := mux.Vars(r)["id"]
    var request struct {
        OngoingService string `json:"ongoing_service"`
    }
    err := json.NewDecoder(r.Body).Decode(&request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    err = handler.manager.AddOngoingService(id, request.OngoingService)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

// SetupRouter sets up the HTTP router
func SetupRouter(handler *APIHandler) *mux.Router {
    r := mux.NewRouter()
    r.HandleFunc("/post_launch_service", handler.CreatePostLaunchServiceHandler).Methods("POST")
    r.HandleFunc("/post_launch_service/{id}", handler.GetPostLaunchServiceHandler).Methods("GET")
    r.HandleFunc("/post_launch_services", handler.ListPostLaunchServicesHandler).Methods("GET")
    r.HandleFunc("/post_launch_service/{id}/ongoing_service", handler.AddOngoingServiceHandler).Methods("POST")
    return r
}

// main initializes and starts the server
func main() {
    manager := NewPostLaunchServiceManager()
    handler := NewAPIHandler(manager)
    router := SetupRouter(handler)

    fmt.Println("Server started at :8080")
    http.ListenAndServe(":8080", router)
}
