package defi_integration

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/scrypt"
)

// LoanStatus represents the status of a loan
type LoanStatus string

const (
	// Pending status for loans that are not yet approved
	Pending LoanStatus = "Pending"
	// Approved status for loans that have been approved
	Approved LoanStatus = "Approved"
	// Repaid status for loans that have been repaid
	Repaid LoanStatus = "Repaid"
	// Defaulted status for loans that have defaulted
	Defaulted LoanStatus = "Defaulted"
)

// Loan represents a loan in the decentralized lending and borrowing system
type Loan struct {
	ID            string     `json:"id"`
	Borrower      string     `json:"borrower"`
	Amount        float64    `json:"amount"`
	InterestRate  float64    `json:"interest_rate"`
	Duration      time.Duration `json:"duration"`
	Status        LoanStatus `json:"status"`
	CreationTime  time.Time  `json:"creation_time"`
	LastUpdated   time.Time  `json:"last_updated"`
	RepaidAmount  float64    `json:"repaid_amount"`
	DueTime       time.Time  `json:"due_time"`
}

// LoanRequest represents a loan request
type LoanRequest struct {
	Borrower     string  `json:"borrower"`
	Amount       float64 `json:"amount"`
	InterestRate float64 `json:"interest_rate"`
	Duration     time.Duration `json:"duration"`
}

// LoanManager manages loans and loan requests
type LoanManager struct {
	Loans map[string]*Loan
	Lock  sync.Mutex
}

// NewLoanManager creates a new LoanManager instance
func NewLoanManager() *LoanManager {
	return &LoanManager{
		Loans: make(map[string]*Loan),
	}
}

// RequestLoan requests a new loan
func (manager *LoanManager) RequestLoan(request LoanRequest) (*Loan, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(request.Borrower + time.Now().String())
	if err != nil {
		return nil, err
	}

	loan := &Loan{
		ID:           id,
		Borrower:     request.Borrower,
		Amount:       request.Amount,
		InterestRate: request.InterestRate,
		Duration:     request.Duration,
		Status:       Pending,
		CreationTime: time.Now(),
		LastUpdated:  time.Now(),
		RepaidAmount: 0,
		DueTime:      time.Now().Add(request.Duration),
	}

	manager.Loans[id] = loan
	return loan, nil
}

// ApproveLoan approves a loan
func (manager *LoanManager) ApproveLoan(id string) (*Loan, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	loan, exists := manager.Loans[id]
	if !exists {
		return nil, errors.New("loan not found")
	}

	loan.Status = Approved
	loan.LastUpdated = time.Now()
	return loan, nil
}

// RepayLoan repays a loan
func (manager *LoanManager) RepayLoan(id string, amount float64) (*Loan, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	loan, exists := manager.Loans[id]
	if !exists {
		return nil, errors.New("loan not found")
	}

	if loan.Status != Approved {
		return nil, errors.New("loan is not approved")
	}

	loan.RepaidAmount += amount
	if loan.RepaidAmount >= loan.Amount*(1+loan.InterestRate/100) {
		loan.Status = Repaid
	}
	loan.LastUpdated = time.Now()
	return loan, nil
}

// DefaultLoan marks a loan as defaulted
func (manager *LoanManager) DefaultLoan(id string) (*Loan, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	loan, exists := manager.Loans[id]
	if !exists {
		return nil, errors.New("loan not found")
	}

	if loan.Status != Approved {
		return nil, errors.New("loan is not approved")
	}

	if time.Now().After(loan.DueTime) && loan.RepaidAmount < loan.Amount*(1+loan.InterestRate/100) {
		loan.Status = Defaulted
		loan.LastUpdated = time.Now()
		return loan, nil
	}

	return nil, errors.New("loan is not due or already repaid")
}

// GetLoan retrieves a loan by ID
func (manager *LoanManager) GetLoan(id string) (*Loan, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	loan, exists := manager.Loans[id]
	if !exists {
		return nil, errors.New("loan not found")
	}
	return loan, nil
}

// ListLoans lists all loans
func (manager *LoanManager) ListLoans() []*Loan {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	loans := make([]*Loan, 0, len(manager.Loans))
	for _, loan := range manager.Loans {
		loans = append(loans, loan)
	}
	return loans
}

// generateUniqueID generates a unique ID using scrypt for the decentralized lending and borrowing entities
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

// APIHandler handles HTTP requests for managing decentralized lending and borrowing
type APIHandler struct {
	manager *LoanManager
}

// NewAPIHandler creates a new APIHandler
func NewAPIHandler(manager *LoanManager) *APIHandler {
	return &APIHandler{manager: manager}
}

// RequestLoanHandler handles loan requests
func (handler *APIHandler) RequestLoanHandler(w http.ResponseWriter, r *http.Request) {
	var request LoanRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newLoan, err := handler.manager.RequestLoan(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newLoan)
}

// ApproveLoanHandler handles loan approval
func (handler *APIHandler) ApproveLoanHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	approvedLoan, err := handler.manager.ApproveLoan(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(approvedLoan)
}

// RepayLoanHandler handles loan repayments
func (handler *APIHandler) RepayLoanHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var payload struct {
		Amount float64 `json:"amount"`
	}
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	repayedLoan, err := handler.manager.RepayLoan(id, payload.Amount)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(repayedLoan)
}

// DefaultLoanHandler handles marking loans as defaulted
func (handler *APIHandler) DefaultLoanHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	defaultedLoan, err := handler.manager.DefaultLoan(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(defaultedLoan)
}

// GetLoanHandler handles retrieving a loan
func (handler *APIHandler) GetLoanHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	loan, err := handler.manager.GetLoan(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(loan)
}

// ListLoansHandler handles listing all loans
func (handler *APIHandler) ListLoansHandler(w http.ResponseWriter, r *http.Request) {
	loans := handler.manager.ListLoans()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(loans)
}

func main() {
	manager := NewLoanManager()
	apiHandler := NewAPIHandler(manager)

	router := mux.NewRouter()
	router.HandleFunc("/loans", apiHandler.RequestLoanHandler).Methods("POST")
	router.HandleFunc("/loans", apiHandler.ListLoansHandler).Methods("GET")
	router.HandleFunc("/loans/{id}", apiHandler.GetLoanHandler).Methods("GET")
	router.HandleFunc("/loans/{id}/approve", apiHandler.ApproveLoanHandler).Methods("POST")
	router.HandleFunc("/loans/{id}/repay", apiHandler.RepayLoanHandler).Methods("POST")
	router.HandleFunc("/loans/{id}/default", apiHandler.DefaultLoanHandler).Methods("POST")

	http.ListenAndServe(":8080", router)
}
