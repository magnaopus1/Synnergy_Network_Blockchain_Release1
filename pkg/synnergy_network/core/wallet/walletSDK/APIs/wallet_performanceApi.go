package wallet_performanceApi

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/gorilla/mux"
    "github.com/synnergy_network/authentication"
    "github.com/synnergy_network/network/logger"
    "github.com/synnergy_network/performance"
    "github.com/synnergy_network/utils"
)

// Structs for request and response
type LoadTestRequest struct {
    Concurrency int           `json:"concurrency"`
    Duration    time.Duration `json:"duration"`
}

type MetricRequest struct {
    MetricName string  `json:"metric_name"`
    Value      float64 `json:"value"`
}

// Initialize the API routes
func SetupRoutes() *mux.Router {
    r := mux.NewRouter()
    
    // Initialize the services
    walletService := utils.NewWalletService()
    blockchainClient := utils.NewBlockchainClient()
    logger := logger.NewLogger()
    blockProcessor := utils.NewBlockProcessor()
    networkManager := utils.NewNetworkManager()
    resourceOptimizer := utils.NewResourceOptimizer()
    maintenanceManager := utils.NewMaintenanceManager()
    
    loadTester := performance.NewLoadTester(walletService, blockchainClient, 10, 5*time.Minute)
    performanceMonitor := performance.NewPerformanceMonitor()
    performanceOptimizer := performance.NewPerformanceOptimizer(blockProcessor, networkManager, resourceOptimizer, maintenanceManager)
    scalabilityService := performance.NewScalabilityService()
    
    // Define the routes
    r.HandleFunc("/loadtest", loadTesterHandler(loadTester)).Methods("POST")
    r.HandleFunc("/recordmetric", recordMetricHandler(performanceMonitor)).Methods("POST")
    r.HandleFunc("/optimizenetwork", optimizeNetworkHandler(performanceOptimizer)).Methods("POST")
    r.HandleFunc("/enhanceblockprocessing", enhanceBlockProcessingHandler(performanceOptimizer)).Methods("POST")
    r.HandleFunc("/conductmaintenance", conductMaintenanceHandler(performanceOptimizer)).Methods("POST")
    r.HandleFunc("/optimizerecourses", optimizeResourcesHandler(scalabilityService)).Methods("POST")
    r.HandleFunc("/adjustblocksizes", adjustBlockSizesHandler(scalabilityService)).Methods("POST")
    r.HandleFunc("/scalehorizontally", scaleHorizontallyHandler(scalabilityService)).Methods("POST")
    r.HandleFunc("/implementsharding", implementShardingHandler(scalabilityService)).Methods("POST")
    
    return r
}

func StartAPIServer() {
    router := SetupRoutes()
    http.ListenAndServe(":8081", router)
}

// Handler for load testing
func loadTesterHandler(lt *performance.LoadTester) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req LoadTestRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        lt.Concurrency = req.Concurrency
        lt.TestDuration = req.Duration

        if err := lt.PerformLoadTest(); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusOK)
    }
}

// Handler for recording metrics
func recordMetricHandler(pm *performance.PerformanceMonitor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req MetricRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        pm.RecordMetric(req.MetricName, req.Value)
        w.WriteHeader(http.StatusOK)
    }
}

// Handler for optimizing network performance
func optimizeNetworkHandler(po *performance.PerformanceOptimizer) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        po.OptimizeNetworkPerformance()
        w.WriteHeader(http.StatusOK)
    }
}

// Handler for enhancing block processing
func enhanceBlockProcessingHandler(po *performance.PerformanceOptimizer) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        po.EnhanceBlockProcessing()
        w.WriteHeader(http.StatusOK)
    }
}

// Handler for conducting regular maintenance
func conductMaintenanceHandler(po *performance.PerformanceOptimizer) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        po.ConductRegularMaintenance()
        w.WriteHeader(http.StatusOK)
    }
}

// Handler for optimizing resources
func optimizeResourcesHandler(ss *performance.ScalabilityService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if err := ss.OptimizeResources(); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        w.WriteHeader(http.StatusOK)
    }
}

// Handler for adjusting block sizes
func adjustBlockSizesHandler(ss *performance.ScalabilityService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if err := ss.AdjustBlockSizes(); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        w.WriteHeader(http.StatusOK)
    }
}

// Handler for scaling horizontally
func scaleHorizontallyHandler(ss *performance.ScalabilityService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if err := ss.ScaleHorizontally(); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        w.WriteHeader(http.StatusOK)
    }
}

// Handler for implementing sharding
func implementShardingHandler(ss *performance.ScalabilityService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if err := ss.ImplementSharding(); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        w.WriteHeader(http.StatusOK)
    }
}
