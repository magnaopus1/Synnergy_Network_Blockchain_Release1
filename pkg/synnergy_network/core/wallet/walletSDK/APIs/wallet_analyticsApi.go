package apis

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"your_project_path/pkg/synnergy_network/core/wallet/analytics"
)

var (
	performMetricsLogger    *analytics.PerformanceLogger
	transactionAnalyticsSvc *analytics.TransactionAnalyticsService
	riskAnalysisSvc         *analytics.RiskAnalysisService
	userBehaviorAnalyticsSvc *analytics.UserBehaviourAnalyticsService
	apiMutex                sync.Mutex
)

func init() {
	// Initialize services and logger
	var err error
	performMetricsLogger, err = analytics.NewPerformanceLogger("performance.log")
	if err != nil {
		panic(err)
	}
	transactionAnalyticsSvc = analytics.NewTransactionAnalyticsService()
	riskAnalysisSvc = analytics.NewRiskAnalysisService()
	userBehaviorAnalyticsSvc = analytics.NewUserBehaviourAnalyticsService()
}

// GetPerformanceMetrics handles the HTTP request for fetching performance metrics.
func GetPerformanceMetrics(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	metrics := analytics.PerformanceMetrics{
		TransactionProcessingTimes: []time.Duration{},
		ResourceUsage:              analytics.MeasureResourceUsage(),
	}

	response, err := json.Marshal(metrics)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

// LogPerformanceMetrics handles the HTTP request for logging performance metrics.
func LogPerformanceMetrics(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	var metrics analytics.PerformanceMetrics
	if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := performMetricsLogger.LogMetrics(metrics); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetTransactionAnalytics handles the HTTP request for fetching transaction analytics.
func GetTransactionAnalytics(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	startTime := time.Now().AddDate(0, -1, 0) // Last 1 month
	endTime := time.Now()

	volume := transactionAnalyticsSvc.TransactionVolume(startTime, endTime)
	averageFee := transactionAnalyticsSvc.AverageTransactionFee(startTime, endTime)
	anomalies := transactionAnalyticsSvc.DetectAnomalies()

	analyticsData := map[string]interface{}{
		"volume":      volume,
		"average_fee": averageFee,
		"anomalies":   anomalies,
	}

	response, err := json.Marshal(analyticsData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

// AddTransaction handles the HTTP request for adding a new transaction to the analytics service.
func AddTransaction(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	var tx analytics.Transaction
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tx.Timestamp = time.Now()
	transactionAnalyticsSvc.AddTransaction(tx)

	w.WriteHeader(http.StatusNoContent)
}

// GetRiskEvents handles the HTTP request for fetching logged risk events.
func GetRiskEvents(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	riskEvents := riskAnalysisSvc.GetRiskEvents()

	response, err := json.Marshal(riskEvents)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

// AnalyzeRisks handles the HTTP request for triggering risk analysis.
func AnalyzeRisks(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	riskAnalysisSvc.AnalyzeRisks()

	w.WriteHeader(http.StatusNoContent)
}

// LogUserActivity handles the HTTP request for logging user activities.
func LogUserActivity(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	var activity analytics.UserActivity
	if err := json.NewDecoder(r.Body).Decode(&activity); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userBehaviorAnalyticsSvc.LogActivity(activity)

	w.WriteHeader(http.StatusNoContent)
}

// GetUserActivities handles the HTTP request for fetching user activities.
func GetUserActivities(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	userID := mux.Vars(r)["userId"]
	userActivities := userBehaviorAnalyticsSvc.GetUserActivities(userID)

	response, err := json.Marshal(userActivities)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

// AnalyzeUserPatterns handles the HTTP request for analyzing user behavior patterns.
func AnalyzeUserPatterns(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	patterns := userBehaviorAnalyticsSvc.AnalyzePatterns()

	response, err := json.Marshal(patterns)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

// RegisterAnalyticsRoutes registers the API routes for the analytics services.
func RegisterAnalyticsRoutes(router *mux.Router) {
	router.HandleFunc("/api/v1/performance/metrics", GetPerformanceMetrics).Methods("GET")
	router.HandleFunc("/api/v1/performance/metrics", LogPerformanceMetrics).Methods("POST")
	router.HandleFunc("/api/v1/transactions/analytics", GetTransactionAnalytics).Methods("GET")
	router.HandleFunc("/api/v1/transactions", AddTransaction).Methods("POST")
	router.HandleFunc("/api/v1/risks", GetRiskEvents).Methods("GET")
	router.HandleFunc("/api/v1/risks/analyze", AnalyzeRisks).Methods("POST")
	router.HandleFunc("/api/v1/user/activities", LogUserActivity).Methods("POST")
	router.HandleFunc("/api/v1/user/activities/{userId}", GetUserActivities).Methods("GET")
	router.HandleFunc("/api/v1/user/patterns", AnalyzeUserPatterns).Methods("GET")
}
