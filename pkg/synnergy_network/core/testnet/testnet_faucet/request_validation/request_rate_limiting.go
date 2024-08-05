package testnet_faucet

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "sync"
    "time"

    "github.com/dgrijalva/jwt-go"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

type FaucetService struct {
    balance             int64
    rateLimit           int64
    requestQueue        chan FaucetRequest
    processedRequests   map[string]time.Time
    mu                  sync.Mutex
    jwtSecret           []byte
    rateLimitWindow     time.Duration
    minRequestInterval  time.Duration
    maxDispenseAmount   int64
}

type FaucetRequest struct {
    UserAddress string
    Amount      int64
    Token       string
}

type UserClaims struct {
    Address string `json:"address"`
    jwt.StandardClaims
}

func NewFaucetService(initialBalance, rateLimit int64, jwtSecret string) *FaucetService {
    return &FaucetService{
        balance:            initialBalance,
        rateLimit:          rateLimit,
        requestQueue:       make(chan FaucetRequest, 100),
        processedRequests:  make(map[string]time.Time),
        jwtSecret:          []byte(jwtSecret),
        rateLimitWindow:    1 * time.Hour,
        minRequestInterval: 10 * time.Minute,
        maxDispenseAmount:  100, // Example amount, adjust as needed
    }
}

func (fs *FaucetService) Start() {
    go fs.processRequests()
}

func (fs *FaucetService) processRequests() {
    for req := range fs.requestQueue {
        if fs.validateRequest(req) {
            fs.dispenseTokens(req.UserAddress, req.Amount)
        }
    }
}

func (fs *FaucetService) validateRequest(req FaucetRequest) bool {
    fs.mu.Lock()
    defer fs.mu.Unlock()

    lastRequest, exists := fs.processedRequests[req.UserAddress]
    if exists && time.Since(lastRequest) < fs.minRequestInterval {
        return false
    }

    if req.Amount > fs.maxDispenseAmount || req.Amount <= 0 {
        return false
    }

    token, err := jwt.ParseWithClaims(req.Token, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
        return fs.jwtSecret, nil
    })
    if err != nil {
        return false
    }

    if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
        if claims.Address != req.UserAddress {
            return false
        }
    } else {
        return false
    }

    fs.processedRequests[req.UserAddress] = time.Now()
    return true
}

func (fs *FaucetService) dispenseTokens(address string, amount int64) {
    fs.mu.Lock()
    defer fs.mu.Unlock()

    if fs.balance >= amount {
        fs.balance -= amount
        fmt.Printf("Dispensed %d tokens to %s\n", amount, address)
        // Add logic to send tokens to the blockchain address
    } else {
        fmt.Printf("Insufficient balance to dispense %d tokens to %s\n", amount, address)
    }
}

func (fs *FaucetService) GenerateJWT(address string) (string, error) {
    claims := UserClaims{
        Address: address,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: time.Now().Add(fs.rateLimitWindow).Unix(),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(fs.jwtSecret)
}

func generateSecureToken() (string, error) {
    token := make([]byte, 32)
    if _, err := rand.Read(token); err != nil {
        return "", err
    }
    hash := sha256.Sum256(token)
    return hex.EncodeToString(hash[:]), nil
}

func hashPassword(password, salt string) (string, error) {
    hash, err := scrypt.Key([]byte(password), []byte(salt), 16384, 8, 1, 32)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(hash), nil
}

func hashWithArgon2(password, salt string) string {
    hash := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}

func generateSalt() (string, error) {
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }
    return hex.EncodeToString(salt), nil
}

func main() {
    faucetService := NewFaucetService(10000, 100, "my_jwt_secret")
    faucetService.Start()

    address := "user1_address"
    amount := int64(50)

    jwtToken, err := faucetService.GenerateJWT(address)
    if err != nil {
        fmt.Println("Error generating JWT:", err)
        return
    }

    faucetRequest := FaucetRequest{
        UserAddress: address,
        Amount:      amount,
        Token:       jwtToken,
    }

    faucetService.requestQueue <- faucetRequest
}
