package resource_forecasting

import (
    "errors"
    "log"
    "sync"
    "time"

    "github.com/synnergy_network/ml"
    "github.com/synnergy_network/monitoring"
    "github.com/synnergy_network/security"
)

// Forecaster manages the forecasting of resource usage.
type Forecaster struct {
    ModelManager     *ml.ModelManager
    MonitoringSystem *monitoring.System
    EncryptionKey    []byte
    Lock             sync.RWMutex
}

// NewForecaster initializes a new Forecaster instance.
func NewForecaster(monitoringSystem *monitoring.System, modelManager *ml.ModelManager, encryptionKey []byte) *Forecaster {
    return &Forecaster{
        MonitoringSystem: monitoringSystem,
        ModelManager:     modelManager,
        EncryptionKey:    encryptionKey,
    }
}

// ForecastResources predicts future resource usage based on historical data.
func (f *Forecaster) ForecastResources() (map[string]float64, error) {
    f.Lock.Lock()
    defer f.Lock.Unlock()

    data, err := f.MonitoringSystem.FetchHistoricalData()
    if err != nil {
        return nil, errors.New("failed to fetch historical data")
    }

    predictions, err := f.ModelManager.Predict("ResourceForecastModel", data)
    if err != nil {
        return nil, errors.New("prediction error")
    }

    return predictions, nil
}

// AdjustResourceAllocation adjusts resources based on forecasted demands.
func (f *Forecaster) AdjustResourceAllocation(predictions map[string]float64) error {
    for resource, predictedUsage := range predictions {
        log.Printf("Adjusting allocation for %s to %f", resource, predictedUsage)
        // Logic to adjust resource allocation, e.g., scaling infrastructure
    }
    return nil
}

// EncryptData securely encrypts sensitive forecasting data.
func (f *Forecaster) EncryptData(data []byte) ([]byte, error) {
    return security.Encrypt(data, f.EncryptionKey)
}

// DecryptData decrypts the encrypted forecasting data.
func (f *Forecaster) DecryptData(data []byte) ([]byte, error) {
    return security.Decrypt(data, f.EncryptionKey)
}

// MonitorAndForecast continuously monitors and forecasts resource usage.
func (f *Forecaster) MonitorAndForecast(interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            predictions, err := f.ForecastResources()
            if err != nil {
                log.Printf("Error in forecasting resources: %v", err)
                continue
            }

            if err := f.AdjustResourceAllocation(predictions); err != nil {
                log.Printf("Error adjusting resources: %v", err)
            }
        }
    }
}
