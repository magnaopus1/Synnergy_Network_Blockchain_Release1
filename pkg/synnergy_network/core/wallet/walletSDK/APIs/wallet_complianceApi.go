package apis

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"your_project_path/pkg/synnergy_network/core/wallet/compliance"
	"your_project_path/utils/logger"
)

var (
	complianceService            *compliance.ComplianceService
	amlKycService                *compliance.AMLKYCService
	auditTrailService            *compliance.AuditTrail
	regulatoryReportingService   *compliance.RegulatoryReportingService
	complianceAPIMutex           sync.Mutex
)

func init() {
	log := logger.NewLogger("compliance_api.log")

	complianceService = compliance.NewComplianceService(log)
	amlKycService = compliance.NewAMLKYCService(log)
	auditTrailService = compliance.NewAuditTrail(log)
	regulatoryReportingService = compliance.NewRegulatoryReportingService(log)
}

// KYCVerificationHandler handles KYC verification requests.
func KYCVerificationHandler(w http.ResponseWriter, r *http.Request) {
	complianceAPIMutex.Lock()
	defer complianceAPIMutex.Unlock()

	var requestData struct {
		UserID string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := amlKycService.VerifyIdentity(requestData.UserID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// AMLCheckHandler handles AML check requests.
func AMLCheckHandler(w http.ResponseWriter, r *http.Request) {
	complianceAPIMutex.Lock()
	defer complianceAPIMutex.Unlock()

	var requestData struct {
		UserID string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := amlKycService.CheckAML(requestData.UserID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ComplianceCheckHandler handles full compliance check requests.
func ComplianceCheckHandler(w http.ResponseWriter, r *http.Request) {
	complianceAPIMutex.Lock()
	defer complianceAPIMutex.Unlock()

	var requestData struct {
		UserID string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := amlKycService.ComplianceCheck(requestData.UserID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// LogTransactionHandler handles requests to log a transaction for audit trails.
func LogTransactionHandler(w http.ResponseWriter, r *http.Request) {
	complianceAPIMutex.Lock()
	defer complianceAPIMutex.Unlock()

	var requestData struct {
		Transaction compliance.Transaction `json:"transaction"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	auditTrailService.LogTransaction(requestData.Transaction)
	w.WriteHeader(http.StatusNoContent)
}

// LogAccessHandler handles requests to log access events.
func LogAccessHandler(w http.ResponseWriter, r *http.Request) {
	complianceAPIMutex.Lock()
	defer complianceAPIMutex.Unlock()

	var requestData struct {
		UserID      string `json:"user_id"`
		Resource    string `json:"resource"`
		AccessType  string `json:"access_type"`
		Allowed     bool   `json:"allowed"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	auditTrailService.LogAccess(requestData.UserID, requestData.Resource, requestData.AccessType, requestData.Allowed)
	w.WriteHeader(http.StatusNoContent)
}

// LogComplianceEventHandler handles requests to log compliance events.
func LogComplianceEventHandler(w http.ResponseWriter, r *http.Request) {
	complianceAPIMutex.Lock()
	defer complianceAPIMutex.Unlock()

	var requestData struct {
		Event   string `json:"event"`
		Details string `json:"details"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	auditTrailService.LogComplianceEvent(requestData.Event, requestData.Details)
	w.WriteHeader(http.StatusNoContent)
}

// GenerateReportHandler handles requests to generate a compliance report.
func GenerateReportHandler(w http.ResponseWriter, r *http.Request) {
	complianceAPIMutex.Lock()
	defer complianceAPIMutex.Unlock()

	var requestData struct {
		StartTime time.Time `json:"start_time"`
		EndTime   time.Time `json:"end_time"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	report, err := regulatoryReportingService.GenerateReport(requestData.StartTime, requestData.EndTime)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{"report": report}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// SubmitReportHandler handles requests to submit a compliance report.
func SubmitReportHandler(w http.ResponseWriter, r *http.Request) {
	complianceAPIMutex.Lock()
	defer complianceAPIMutex.Unlock()

	var requestData struct {
		Report compliance.Report `json:"report"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := regulatoryReportingService.SubmitReport(&requestData.Report); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RegisterComplianceRoutes registers the API routes for the compliance services.
func RegisterComplianceRoutes(router *mux.Router) {
	router.HandleFunc("/api/v1/compliance/kyc", KYCVerificationHandler).Methods("POST")
	router.HandleFunc("/api/v1/compliance/aml", AMLCheckHandler).Methods("POST")
	router.HandleFunc("/api/v1/compliance/check", ComplianceCheckHandler).Methods("POST")
	router.HandleFunc("/api/v1/compliance/audit/log_transaction", LogTransactionHandler).Methods("POST")
	router.HandleFunc("/api/v1/compliance/audit/log_access", LogAccessHandler).Methods("POST")
	router.HandleFunc("/api/v1/compliance/audit/log_event", LogComplianceEventHandler).Methods("POST")
	router.HandleFunc("/api/v1/compliance/report/generate", GenerateReportHandler).Methods("POST")
	router.HandleFunc("/api/v1/compliance/report/submit", SubmitReportHandler).Methods("POST")
}
