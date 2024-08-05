package anomalydetection

import (
    "errors"
    "log"
    "math"
    "time"

    "github.com/yourorg/yourproject/cryptography"
    "github.com/yourorg/yourproject/datastore"
    "github.com/yourorg/yourproject/models"
)

// AnomalyDetectionService handles the detection of anomalies within the blockchain network
type AnomalyDetectionService struct {
    threshold float64
    window    time.Duration
    datastore *datastore.DataStore
}

// NewAnomalyDetectionService initializes a new anomaly detection service
func NewAnomalyDetectionService(threshold float64, window time.Duration, ds *datastore.DataStore) *AnomalyDetectionService {
    return &AnomalyDetectionService{
        threshold: threshold,
        window:    window,
        datastore: ds,
    }
}

// DetectAnomalies runs anomaly detection on the latest transactions
func (ads *AnomalyDetectionService) DetectAnomalies() ([]models.Transaction, error) {
    transactions, err := ads.datastore.GetRecentTransactions(ads.window)
    if err != nil {
        return nil, err
    }

    anomalies := []models.Transaction{}
    for _, tx := range transactions {
        if ads.isAnomalous(tx) {
            anomalies = append(anomalies, tx)
        }
    }

    return anomalies, nil
}

// isAnomalous checks if a transaction is anomalous based on certain criteria
func (ads *AnomalyDetectionService) isAnomalous(tx models.Transaction) bool {
    // Example criteria: deviation from average transaction size
    avgSize, err := ads.datastore.GetAverageTransactionSize(ads.window)
    if err != nil {
        log.Printf("Error retrieving average transaction size: %v", err)
        return false
    }

    deviation := math.Abs(float64(tx.Size)-avgSize) / avgSize
    if deviation > ads.threshold {
        ads.alert(tx)
        return true
    }

    return false
}

// alert sends an alert about a potential anomaly
func (ads *AnomalyDetectionService) alert(tx models.Transaction) {
    // Implementation of alert mechanism
    // This could include sending notifications to admins, logging, etc.
    log.Printf("Anomalous transaction detected: %v", tx)
}

// TrainModel trains a machine learning model on past transaction data
func (ads *AnomalyDetectionService) TrainModel() error {
    data, err := ads.datastore.GetTrainingData()
    if err != nil {
        return err
    }

    model := cryptography.NewAnomalyDetectionModel()
    err = model.Train(data)
    if err != nil {
        return errors.New("model training failed: " + err.Error())
    }

    err = ads.datastore.SaveModel(model)
    if err != nil {
        return errors.New("failed to save trained model: " + err.Error())
    }

    return nil
}

// PredictAnomaly uses a trained model to predict if a transaction is anomalous
func (ads *AnomalyDetectionService) PredictAnomaly(tx models.Transaction) (bool, error) {
    model, err := ads.datastore.LoadModel()
    if err != nil {
        return false, errors.New("failed to load model: " + err.Error())
    }

    isAnomalous, err := model.Predict(tx)
    if err != nil {
        return false, errors.New("prediction failed: " + err.Error())
    }

    if isAnomalous {
        ads.alert(tx)
    }

    return isAnomalous, nil
}
