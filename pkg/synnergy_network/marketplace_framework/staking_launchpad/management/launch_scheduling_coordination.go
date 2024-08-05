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

// LaunchEvent represents a scheduled launch event.
type LaunchEvent struct {
    ID          string    `json:"id"`
    ProjectName string    `json:"project_name"`
    Description string    `json:"description"`
    ScheduledAt time.Time `json:"scheduled_at"`
    Encrypted   bool      `json:"encrypted"`
}

// LaunchEventRequest represents a request for scheduling a launch event.
type LaunchEventRequest struct {
    ProjectName string `json:"project_name"`
    Description string `json:"description"`
    ScheduledAt string `json:"scheduled_at"`
}

// LaunchEventManager manages the scheduling and coordination of launch events.
type LaunchEventManager struct {
    Events map[string]*LaunchEvent
    Lock   sync.Mutex
}

// NewLaunchEventManager creates a new instance of LaunchEventManager.
func NewLaunchEventManager() *LaunchEventManager {
    return &LaunchEventManager{
        Events: make(map[string]*LaunchEvent),
    }
}

// ScheduleLaunchEvent schedules a new launch event.
func (manager *LaunchEventManager) ScheduleLaunchEvent(request LaunchEventRequest, encrypt bool) (*LaunchEvent, error) {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    scheduledAt, err := time.Parse(time.RFC3339, request.ScheduledAt)
    if err != nil {
        return nil, err
    }

    id, err := generateUniqueID(request.ProjectName + request.Description + time.Now().String())
    if err != nil {
        return nil, err
    }

    var description string
    if encrypt {
        encryptedDescription, err := encryptData(request.Description, id)
        if err != nil {
            return nil, err
        }
        description = encryptedDescription
    } else {
        description = request.Description
    }

    event := &LaunchEvent{
        ID:          id,
        ProjectName: request.ProjectName,
        Description: description,
        ScheduledAt: scheduledAt,
        Encrypted:   encrypt,
    }

    manager.Events[id] = event
    return event, nil
}

// GetLaunchEvent retrieves a launch event by ID.
func (manager *LaunchEventManager) GetLaunchEvent(id string) (*LaunchEvent, error) {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    event, exists := manager.Events[id]
    if !exists {
        return nil, errors.New("event not found")
    }
    return event, nil
}

// ListLaunchEvents lists all scheduled launch events.
func (manager *LaunchEventManager) ListLaunchEvents() []*LaunchEvent {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    events := make([]*LaunchEvent, 0, len(manager.Events))
    for _, event := range manager.Events {
        events = append(events, event)
    }
    return events
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

// APIHandler handles HTTP requests for launch events.
type APIHandler struct {
    manager *LaunchEventManager
}

// NewAPIHandler creates a new APIHandler.
func NewAPIHandler(manager *LaunchEventManager) *APIHandler {
    return &APIHandler{manager: manager}
}

// ScheduleLaunchEventHandler handles scheduling launch events.
func (handler *APIHandler) ScheduleLaunchEventHandler(w http.ResponseWriter, r *http.Request) {
    var request LaunchEventRequest
    err := json.NewDecoder(r.Body).Decode(&request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    encrypt := r.URL.Query().Get("encrypt") == "true"
    newEvent, err := handler.manager.ScheduleLaunchEvent(request, encrypt)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(newEvent)
}

// GetLaunchEventHandler handles retrieving a launch event.
func (handler *APIHandler) GetLaunchEventHandler(w http.ResponseWriter, r *http.Request) {
    id := mux.Vars(r)["id"]
    event, err := handler.manager.GetLaunchEvent(id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(event)
}

// ListLaunchEventsHandler handles listing all scheduled launch events.
func (handler *APIHandler) ListLaunchEventsHandler(w http.ResponseWriter, r *http.Request) {
    events := handler.manager.ListLaunchEvents()
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(events)
}

// SetupRouter sets up the HTTP router.
func SetupRouter(handler *APIHandler) *mux.Router {
    r := mux.NewRouter()
    r.HandleFunc("/launch_event", handler.ScheduleLaunchEventHandler).Methods("POST")
    r.HandleFunc("/launch_event/{id}", handler.GetLaunchEventHandler).Methods("GET")
    r.HandleFunc("/launch_events", handler.ListLaunchEventsHandler).Methods("GET")
    return r
}

// main initializes and starts the server.
func main() {
    manager := NewLaunchEventManager()
    handler := NewAPIHandler(manager)
    router := SetupRouter(handler)

    fmt.Println("Server started at :8080")
    http.ListenAndServe(":8080", router)
}
