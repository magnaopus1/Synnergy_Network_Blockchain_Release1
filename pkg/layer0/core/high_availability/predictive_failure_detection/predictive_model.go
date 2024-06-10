package high_availability

import (
    "bytes"
    "context"
    "encoding/json"
    "io/ioutil"
    "log"
    "net/http"
    "time"
)

type PredictorClient struct {
    ServerURL string
}

type PredictionRequest struct {
    Features []float64 `json:"features"`
}

type PredictionResponse struct {
    Prediction []int `json:"prediction"`
}

// NewPredictorClient creates a new client to interact with the Python prediction server.
func NewPredictorClient(serverURL string) *PredictorClient {
    return &PredictorClient{ServerURL: serverURL}
}

// Predict uses the Python ML model to predict node failures.
func (pc *PredictorClient) Predict(features []float64) ([]int, error) {
    requestData, err := json.Marshal(PredictionRequest{Features: features})
    if err != nil {
        return nil, err
    }

    response, err := http.Post(pc.ServerURL+"/predict", "application/json", bytes.NewBuffer(requestData))
    if err != nil {
        return nil, err
    }
    defer response.Body.Close()

    responseData, err := ioutil.ReadAll(response.Body)
    if err != nil {
        return nil, err
    }

    var prediction PredictionResponse
    if err := json.Unmarshal(responseData, &prediction); err != nil {
        return nil, err
    }

    return prediction.Prediction, nil
}

func main() {
    client := NewPredictorClient("http://localhost:5000")
    // Example features, replace with real data as necessary
    features := []float64{0.5, 0.3, 0.2}

    prediction, err := client.Predict(features)
    if err != nil {
        log.Fatalf("Failed to get prediction: %v", err)
    }
    log.Printf("Prediction result: %v\n", prediction)
}
