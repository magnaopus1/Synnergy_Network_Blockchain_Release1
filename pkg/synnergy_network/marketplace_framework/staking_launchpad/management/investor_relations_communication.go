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

// InvestorMessage represents a message sent to investors in the staking launchpad.
type InvestorMessage struct {
    ID        string    `json:"id"`
    Subject   string    `json:"subject"`
    Body      string    `json:"body"`
    Sender    string    `json:"sender"`
    SentAt    time.Time `json:"sent_at"`
    Encrypted bool      `json:"encrypted"`
}

// InvestorMessageRequest represents a request for sending an investor message.
type InvestorMessageRequest struct {
    Subject string `json:"subject"`
    Body    string `json:"body"`
    Sender  string `json:"sender"`
}

// InvestorMessageManager manages the sending and retrieval of investor messages.
type InvestorMessageManager struct {
    Messages map[string]*InvestorMessage
    Lock     sync.Mutex
}

// NewInvestorMessageManager creates a new instance of InvestorMessageManager.
func NewInvestorMessageManager() *InvestorMessageManager {
    return &InvestorMessageManager{
        Messages: make(map[string]*InvestorMessage),
    }
}

// SendInvestorMessage sends a new message to investors.
func (manager *InvestorMessageManager) SendInvestorMessage(request InvestorMessageRequest, encrypt bool) (*InvestorMessage, error) {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    id, err := generateUniqueID(request.Subject + request.Sender + time.Now().String())
    if err != nil {
        return nil, err
    }

    var body string
    if encrypt {
        encryptedBody, err := encryptData(request.Body, id)
        if err != nil {
            return nil, err
        }
        body = encryptedBody
    } else {
        body = request.Body
    }

    message := &InvestorMessage{
        ID:        id,
        Subject:   request.Subject,
        Body:      body,
        Sender:    request.Sender,
        SentAt:    time.Now(),
        Encrypted: encrypt,
    }

    manager.Messages[id] = message
    return message, nil
}

// GetInvestorMessage retrieves an investor message by ID.
func (manager *InvestorMessageManager) GetInvestorMessage(id string) (*InvestorMessage, error) {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    message, exists := manager.Messages[id]
    if !exists {
        return nil, errors.New("message not found")
    }
    return message, nil
}

// ListInvestorMessages lists all investor messages.
func (manager *InvestorMessageManager) ListInvestorMessages() []*InvestorMessage {
    manager.Lock.Lock()
    defer manager.Lock.Unlock()

    messages := make([]*InvestorMessage, 0, len(manager.Messages))
    for _, message := range manager.Messages {
        messages = append(messages, message)
    }
    return messages
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

// APIHandler handles HTTP requests for investor messages.
type APIHandler struct {
    manager *InvestorMessageManager
}

// NewAPIHandler creates a new APIHandler.
func NewAPIHandler(manager *InvestorMessageManager) *APIHandler {
    return &APIHandler{manager: manager}
}

// SendInvestorMessageHandler handles sending investor messages.
func (handler *APIHandler) SendInvestorMessageHandler(w http.ResponseWriter, r *http.Request) {
    var request InvestorMessageRequest
    err := json.NewDecoder(r.Body).Decode(&request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    encrypt := r.URL.Query().Get("encrypt") == "true"
    newMessage, err := handler.manager.SendInvestorMessage(request, encrypt)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(newMessage)
}

// GetInvestorMessageHandler handles retrieving an investor message.
func (handler *APIHandler) GetInvestorMessageHandler(w http.ResponseWriter, r *http.Request) {
    id := mux.Vars(r)["id"]
    message, err := handler.manager.GetInvestorMessage(id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(message)
}

// ListInvestorMessagesHandler handles listing all investor messages.
func (handler *APIHandler) ListInvestorMessagesHandler(w http.ResponseWriter, r *http.Request) {
    messages := handler.manager.ListInvestorMessages()
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(messages)
}

// SetupRouter sets up the HTTP router.
func SetupRouter(handler *APIHandler) *mux.Router {
    r := mux.NewRouter()
    r.HandleFunc("/investor_message", handler.SendInvestorMessageHandler).Methods("POST")
    r.HandleFunc("/investor_message/{id}", handler.GetInvestorMessageHandler).Methods("GET")
    r.HandleFunc("/investor_messages", handler.ListInvestorMessagesHandler).Methods("GET")
    return r
}

// main initializes and starts the server.
func main() {
    manager := NewInvestorMessageManager()
    handler := NewAPIHandler(manager)
    router := SetupRouter(handler)

    fmt.Println("Server started at :8080")
    http.ListenAndServe(":8080", router)
}
