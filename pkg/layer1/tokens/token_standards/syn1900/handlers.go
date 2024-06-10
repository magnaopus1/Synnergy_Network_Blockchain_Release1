package syn1900

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
	"log"
	"github.com/gorilla/mux"
)

// DBClient encapsulates the database client to be used for database operations.
var dbClient *DBClient

// InitializeHandlers sets up the routes and initializes the database client.
func InitializeHandlers(router *mux.Router, db *DBClient) {
	dbClient = db
	router.HandleFunc("/issueCredit", Authenticate(IssueCreditHandler)).Methods("POST")
	router.HandleFunc("/getCredit/{creditId}", Authenticate(GetCreditHandler)).Methods("GET")
	router.HandleFunc("/revokeCredit/{creditId}", Authenticate(RevokeCreditHandler)).Methods("DELETE")
	router.HandleFunc("/listCredits/{recipientId}", Authenticate(ListCreditsHandler)).Methods("GET")
}

// Authenticate is a middleware to verify if the request is from an authorized source.
func Authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Implement authentication logic here
		// If authentication fails, return an error
		next(w, r)
	}
}

// IssueCreditHandler handles requests to issue a new education credit.
func IssueCreditHandler(w http.ResponseWriter, r *http.Request) {
	var credit EducationCredit
	if err := json.NewDecoder(r.Body).Decode(&credit); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	credit.IssueDate = time.Now() // Set the issue date to the current time

	if err := dbClient.SaveCredit(credit); err != nil {
		http.Error(w, "Failed to issue credit: "+err.Error(), http.StatusInternalServerError)
		log.Printf("IssueCredit failed: %v", err)
		return
	}

	log.Printf("Credit issued: %v", credit.CreditID)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(credit)
}

// GetCreditHandler handles requests to retrieve a specific education credit by ID.
func GetCreditHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	creditID := vars["creditId"]
	credit, err := dbClient.GetCredit(creditID)
	if err != nil {
		http.Error(w, "Credit not found: "+err.Error(), http.StatusNotFound)
		log.Printf("GetCredit failed: %v", err)
		return
	}

	log.Printf("Credit retrieved: %v", credit.CreditID)
	json.NewEncoder(w).Encode(credit)
}

// RevokeCreditHandler handles requests to revoke an education credit.
func RevokeCreditHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	creditID := vars["creditId"]
	if err := dbClient.DeleteCredit(creditID); err != nil {
		http.Error(w, "Failed to revoke credit: "+err.Error(), http.StatusInternalServerError)
		log.Printf("RevokeCredit failed: %v", err)
		return
	}

	log.Printf("Credit revoked: %v", creditID)
	w.WriteHeader(http.StatusOK)
}

// ListCreditsHandler lists all credits issued to a particular recipient.
func ListCreditsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	recipientID := vars["recipientId"]
	credits, err := dbClient.ListCreditsForRecipient(recipientID)
	if err != nil {
		http.Error(w, "No credits found: "+err.Error(), http.StatusNotFound)
		log.Printf("ListCredits failed: %v", err)
		return
	}

	log.Printf("Credits listed for: %v", recipientID)
	json.NewEncoder(w).Encode(credits)
}
