package walletSDK

import (
	"encoding/json"
	"net/http"
	"github.com/gorilla/mux"
	"github.com/synnergy_network/core/wallet/transaction"
	"github.com/synnergy_network/utils"
)

// Initialize services
var (
	blockchainService         = transaction.NewBlockchainService()
	auditService              = transaction.NewAuditTrailService()
	monitoringService         = transaction.NewTransactionMonitoringService()
	walletService             = transaction.NewWalletService()
	validatorService          = transaction.NewValidator(blockchainService)
	sendTransactionService    = transaction.NewSendTransactionService(walletService)
	receiveTransactionService = transaction.NewReceiveTransactionService(walletService)
	reversalService           = transaction.NewTransactionReversalService(blockchainService, walletService, auditService, monitoringService)
	dynamicFeeService         = transaction.NewDynamicFeeAdjustmentService(blockchainService, walletService, 0.001, 0.01)
	reportService             = transaction.NewReportService()
	transactionManager        = transaction.NewTransactionManager("transactions.json")
	transactionHistory        = transaction.NewTransactionHistory("transaction_history.json")
)

// ApplyForReversalHandler handles transaction reversal application requests
func ApplyForReversalHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TransactionID string `json:"transaction_id"`
		Requester     string `json:"requester"`
		Reason        string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	reversalID, err := reversalService.ApplyForTransactionReversal(req.TransactionID, req.Requester, req.Reason)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"reversal_id": reversalID})
}

// ProcessReversalHandler handles processing of transaction reversal requests
func ProcessReversalHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RequestID string `json:"request_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := reversalService.ProcessReversalRequest(req.RequestID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Reversal processed"})
}

// CancelTransactionHandler handles transaction cancellation requests
func CancelTransactionHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TransactionID  string `json:"transaction_id"`
		UserPrivateKey string `json:"user_private_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := sendTransactionService.CancelTransaction(req.TransactionID, req.UserPrivateKey); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Transaction cancelled"})
}

// ConvertToPrivateTransactionHandler handles conversion of transactions to private transactions
func ConvertToPrivateTransactionHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TransactionID string `json:"transaction_id"`
		Passphrase    string `json:"passphrase"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := transactionManager.ConvertToPrivateTransaction(req.TransactionID, req.Passphrase); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Transaction converted to private"})
}

// SendTransactionHandler handles sending of transactions
func SendTransactionHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From   string  `json:"from"`
		To     string  `json:"to"`
		Amount float64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	tx, err := sendTransactionService.CreateTransaction(req.From, req.To, req.Amount)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := sendTransactionService.SendTransaction(tx); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tx)
}

// ReceiveTransactionHandler handles receiving of transactions
func ReceiveTransactionHandler(w http.ResponseWriter, r *http.Request) {
	var tx transaction.Transaction
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := receiveTransactionService.ReceiveTransaction(&tx); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Transaction received"})
}

// ListReversalRequestsHandler lists all transaction reversal requests
func ListReversalRequestsHandler(w http.ResponseWriter, r *http.Request) {
	requests, err := reversalService.ListReversalRequests()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(requests)
}

// ReportTransactionHandler handles reporting of suspicious transactions
func ReportTransactionHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TransactionID string `json:"transaction_id"`
		Reason        string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	reportID, err := reportService.ReportTransaction(req.TransactionID, req.Reason)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"report_id": reportID})
}

// ReviewReportHandler handles review of reported transactions
func ReviewReportHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReportID string `json:"report_id"`
		Status   string `json:"status"`
		Reviewer string `json:"reviewer"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := reportService.ReviewReport(req.ReportID, req.Status, req.Reviewer); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Report reviewed"})
}

// TransactionHistoryHandler handles retrieval of transaction history
func TransactionHistoryHandler(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	if address == "" {
		http.Error(w, "Address is required", http.StatusBadRequest)
		return
	}

	transactions, err := transactionHistory.GetTransactionsByAddress(address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(transactions)
}

// TransactionDetailsHandler handles retrieval of transaction details by ID
func TransactionDetailsHandler(w http.ResponseWriter, r *http.Request) {
	transactionID := mux.Vars(r)["id"]
	transaction, err := transactionManager.GetTransaction(transactionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(transaction)
}

// SetupTransactionRoutes sets up the routes for the wallet transaction API
func SetupTransactionRoutes() *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/transaction/reversal/apply", ApplyForReversalHandler).Methods("POST")
	r.HandleFunc("/transaction/reversal/process", ProcessReversalHandler).Methods("POST")
	r.HandleFunc("/transaction/cancel", CancelTransactionHandler).Methods("POST")
	r.HandleFunc("/transaction/private/convert", ConvertToPrivateTransactionHandler).Methods("POST")
	r.HandleFunc("/transaction/send", SendTransactionHandler).Methods("POST")
	r.HandleFunc("/transaction/receive", ReceiveTransactionHandler).Methods("POST")
	r.HandleFunc("/transaction/reversal/requests", ListReversalRequestsHandler).Methods("GET")
	r.HandleFunc("/transaction/report", ReportTransactionHandler).Methods("POST")
	r.HandleFunc("/transaction/report/review", ReviewReportHandler).Methods("POST")
	r.HandleFunc("/transaction/history", TransactionHistoryHandler).Methods("GET")
	r.HandleFunc("/transaction/{id}", TransactionDetailsHandler).Methods("GET")

	return r
}

// StartTransactionAPIServer starts the API server for wallet transactions
func StartTransactionAPIServer() {
	router := SetupTransactionRoutes()
	http.ListenAndServe(":8085", router)
}
