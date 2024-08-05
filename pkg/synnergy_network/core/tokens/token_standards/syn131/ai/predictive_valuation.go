package ai

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "time"

    "github.com/syndtr/goleveldb/leveldb"
)

type Asset struct {
    ID              string    `json:"id"`
    HistoricalValues []float64 `json:"historical_values"`
    Timestamps      []time.Time `json:"timestamps"`
}

const (
    valuationDataFile = "valuation_data.json"
    assetDB           = "asset_db"
    apiURL            = "https://external-api.example.com" // Replace with the actual API URL
)

var valuationData map[string]Asset

func init() {
    valuationData = make(map[string]Asset)
}

func InitValuationData() error {
    file, err := os.Open(valuationDataFile)
    if err != nil {
        if os.IsNotExist(err) {
            return nil
        }
        return err
    }
    defer file.Close()
    return json.NewDecoder(file).Decode(&valuationData)
}

func SaveValuationData() error {
    file, err := os.Create(valuationDataFile)
    if err != nil {
        return err
    }
    defer file.Close()
    return json.NewEncoder(file).Encode(&valuationData)
}

func RecordAssetValuationData(id string, value float64, timestamp time.Time) error {
    db, err := leveldb.OpenFile(assetDB, nil)
    if err != nil {
        return err
    }
    defer db.Close()

    asset, exists := valuationData[id]
    if !exists {
        asset = Asset{
            ID:              id,
            HistoricalValues: []float64{},
            Timestamps:      []time.Time{},
        }
    }

    asset.HistoricalValues = append(asset.HistoricalValues, value)
    asset.Timestamps = append(asset.Timestamps, timestamp)
    valuationData[id] = asset

    if err := SaveValuationData(); err != nil {
        return err
    }

    assetData, err := json.Marshal(asset)
    if err != nil {
        return err
    }

    return db.Put([]byte(id), assetData, nil)
}

func PredictFutureValuation(id string, futureTime time.Time) (float64, error) {
    asset, exists := valuationData[id]
    if !exists {
        return 0, errors.New("asset data not found")
    }

    requestData := map[string]interface{}{
        "id":        id,
        "values":    asset.HistoricalValues,
        "timestamps": asset.Timestamps,
        "future_time": futureTime,
    }

    requestBody, err := json.Marshal(requestData)
    if err != nil {
        return 0, err
    }

    resp, err := http.Post(fmt.Sprintf("%s/predict", apiURL), "application/json", bytes.NewBuffer(requestBody))
    if err != nil {
        return 0, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return 0, fmt.Errorf("failed to get prediction: status code %d", resp.StatusCode)
    }

    var response map[string]float64
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return 0, err
    }
    if err := json.Unmarshal(body, &response); err != nil {
        return 0, err
    }

    predictedValue, ok := response["predicted_value"]
    if !ok {
        return 0, errors.New("predicted value not found in response")
    }

    return predictedValue, nil
}

func ProvideValuationInsights(id string) (map[string]float64, error) {
    asset, exists := valuationData[id]
    if !exists {
        return nil, errors.New("asset data not found")
    }

    requestData := map[string]interface{}{
        "id":        id,
        "values":    asset.HistoricalValues,
        "timestamps": asset.Timestamps,
    }

    requestBody, err := json.Marshal(requestData)
    if err != nil {
        return nil, err
    }

    resp, err := http.Post(fmt.Sprintf("%s/insights", apiURL), "application/json", bytes.NewBuffer(requestBody))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("failed to get insights: status code %d", resp.StatusCode)
    }

    var insights map[string]float64
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    if err := json.Unmarshal(body, &insights); err != nil {
        return nil, err
    }

    return insights, nil
}

func main() {
    if err := InitValuationData(); err != nil {
        log.Fatalf("failed to initialize valuation data: %v", err)
    }
}
