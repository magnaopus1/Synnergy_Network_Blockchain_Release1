package syn1401

import (
    "database/sql"
    "fmt"
    "log"
    "net/http"
)

// TokenHandler manages the HTTP interface for interacting with investment tokens.
type TokenHandler struct {
    storage *TokenStorage
}

// NewTokenHandler creates a new handler with access to a token storage system.
func NewTokenHandler(db *sql.DB) *TokenHandler {
    return &TokenHandler{
        storage: NewTokenStorage(db),
    }
}

// HandleCreateToken processes the creation of a new investment token.
func (th *TokenHandler) HandleCreateToken(w http.ResponseWriter, r *http.Request) {
    // Simulate request parsing
    id := "token" + fmt.Sprint(rand.Intn(1000))
    owner := "user" + fmt.Sprint(rand.Intn(100))
    principal := 1000.00
    interestRate := 0.05
    durationDays := 365

    token := NewInvestmentToken(id, owner, principal, interestRate, durationDays)
    if err := th.storage.SaveToken(token); err != nil {
        http.Error(w, "Failed to create token: "+err.Error(), http.StatusInternalServerError)
        return
    }

    log.Printf("New investment token created with ID: %s", token.ID)
    fmt.Fprintf(w, "Token created with ID: %s\n", token.ID)
}

// HandleTransferOwnership processes ownership transfer requests for tokens.
func (th *TokenHandler) HandleTransferOwnership(w http.ResponseWriter, r *http.Request) {
    // Simulate request parsing
    tokenID := "token123"
    newOwner := "user" + fmt.Sprint(rand.Intn(100))

    token, err := th.storage.FetchToken(tokenID)
    if err != nil {
        http.Error(w, "Token not found", http.StatusNotFound)
        return
    }

    token.TransferOwnership(newOwner)
    if err := th.storage.UpdateToken(token); err != nil {
        http.Error(w, "Failed to transfer ownership: "+err.Error(), http.StatusInternalServerError)
        return
    }

    log.Printf("Ownership of token %s transferred to %s", tokenID, newOwner)
    fmt.Fprintf(w, "Token %s ownership transferred to %s\n", tokenID, newOwner)
}

// HandleGetTokenDetails processes requests to get token details.
func (th *TokenHandler) HandleGetTokenDetails(w http.ResponseWriter, r *http.Request) {
    // Simulate request parsing
    tokenID := r.URL.Query().Get("tokenID")

    token, err := th.storage.FetchToken(tokenID)
    if err != nil {
        http.Error(w, "Token not found", http.StatusNotFound)
        return
    }

    details := token.GetDetails()
    log.Printf("Retrieved details for token %s", tokenID)
    fmt.Fprintf(w, "Token details: %+v\n", details)
}

// SetupRoutes initializes the routes for the token API.
func (th *TokenHandler) SetupRoutes(mux *http.ServeMux) {
    mux.HandleFunc("/createToken", th.HandleCreateToken)
    mux.HandleFunc("/transferOwnership", th.HandleTransferOwnership)
    mux.HandleFunc("/getTokenDetails", th.HandleGetTokenDetails)
}

// Example of setting up the server and handling requests.
func ExampleServer() {
    db, err := sql.Open("sqlite3", "path_to_db.db")
    if err != nil {
        log.Fatal("Failed to open database:", err)
    }

    handler := NewTokenHandler(db)
    mux := http.NewServeMux()
    handler.SetupRoutes(mux)

    log.Println("Starting server on :8080")
    if err := http.ListenAndServe(":8080", mux); err != nil {
        log.Fatal("Server failed:", err)
    }
}
