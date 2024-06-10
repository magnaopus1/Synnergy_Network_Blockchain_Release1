package sustainability_metrics

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/blockchain"
	"github.com/synthron_blockchain_final/pkg/layer0/green_technology/sustainability_metrics/reporting_tools/encryption"
)

// SustainabilityData represents the collected data for sustainability metrics.
type SustainabilityData struct {
	Timestamp     time.Time `json:"timestamp"`
	EnergyUsage   float64   `json:"energy_usage"`
	CarbonEmitted float64   `json:"carbon_emitted"`
	WaterUsage    float64   `json:"water_usage"`
	AirQuality    float64   `json:"air_quality"`
}

// SustainabilityReport represents a report of sustainability metrics over a period.
type SustainabilityReport struct {
	StartDate        time.Time `json:"start_date"`
	EndDate          time.Time `json:"end_date"`
	TotalEnergyUsage float64   `json:"total_energy_usage"`
	TotalCarbonEmitted float64   `json:"total_carbon_emitted"`
	TotalWaterUsage  float64   `json:"total_water_usage"`
	AverageAirQuality float64   `json:"average_air_quality"`
}

// DataCollector is responsible for collecting sustainability data.
type DataCollector struct {
	DataSources []DataSource
}

// DataSource represents a source of sustainability data.
type DataSource struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
}

// NewDataCollector creates a new DataCollector.
func NewDataCollector(dataSources []DataSource) *DataCollector {
	return &DataCollector{DataSources: dataSources}
}

// CollectData collects data from all data sources and stores it on the blockchain.
func (dc *DataCollector) CollectData() error {
	for _, source := range dc.DataSources {
		data, err := dc.fetchDataFromSource(source)
		if err != nil {
			return err
		}

		err = dc.storeDataOnBlockchain(data)
		if err != nil {
			return err
		}
	}

	return nil
}

// fetchDataFromSource fetches data from a given data source.
func (dc *DataCollector) fetchDataFromSource(source DataSource) (*SustainabilityData, error) {
	// Mock implementation for data fetching. Replace with actual data fetching logic.
	// For instance, it can fetch data from an IoT device or an API endpoint.

	// Mock data
	data := &SustainabilityData{
		Timestamp:     time.Now(),
		EnergyUsage:   100.0,
		CarbonEmitted: 50.0,
		WaterUsage:    20.0,
		AirQuality:    1.0,
	}

	return data, nil
}

// storeDataOnBlockchain stores the collected data on the blockchain.
func (dc *DataCollector) storeDataOnBlockchain(data *SustainabilityData) error {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	encryptedData, err := encryption.Encrypt(dataJSON)
	if err != nil {
		return err
	}

	dataKey := fmt.Sprintf("sustainability_data_%d", time.Now().Unix())
	err = blockchain.PutState(dataKey, encryptedData)
	if err != nil {
		return err
	}

	return nil
}

// ListAllData lists all sustainability data collected and stored on the blockchain.
func ListAllData() ([]SustainabilityData, error) {
	keys, err := blockchain.GetAllKeys()
	if err != nil {
		return nil, err
	}

	var allData []SustainabilityData
	for _, key := range keys {
		dataBytes, err := blockchain.GetState(key)
		if err != nil {
			continue
		}

		decryptedData, err := encryption.Decrypt(dataBytes)
		if err != nil {
			continue
		}

		var data SustainabilityData
		err = json.Unmarshal(decryptedData, &data)
		if err != nil {
			continue
		}

		allData = append(allData, data)
	}

	return allData, nil
}

// ReportingTool provides functionality to generate sustainability reports.
type ReportingTool struct {
}

// NewReportingTool creates a new ReportingTool.
func NewReportingTool() *ReportingTool {
	return &ReportingTool{}
}

// GenerateReport generates a sustainability report.
func (rt *ReportingTool) GenerateReport(startDate, endDate time.Time) (*SustainabilityReport, error) {
	data, err := ListAllData()
	if err != nil {
		return nil, err
	}

	var filteredData []SustainabilityData
	for _, d := range data {
		if d.Timestamp.After(startDate) && d.Timestamp.Before(endDate) {
			filteredData = append(filteredData, d)
		}
	}

	totalEnergyUsage := 0.0
	totalCarbonEmitted := 0.0
	totalWaterUsage := 0.0
	totalAirQuality := 0.0

	for _, d := range filteredData {
		totalEnergyUsage += d.EnergyUsage
		totalCarbonEmitted += d.CarbonEmitted
		totalWaterUsage += d.WaterUsage
		totalAirQuality += d.AirQuality
	}

	report := &SustainabilityReport{
		StartDate:        startDate,
		EndDate:          endDate,
		TotalEnergyUsage: totalEnergyUsage,
		TotalCarbonEmitted: totalCarbonEmitted,
		TotalWaterUsage:  totalWaterUsage,
		AverageAirQuality: totalAirQuality / float64(len(filteredData)),
	}

	return report, nil
}

// HandleDataCollectionRequest handles data collection requests.
func HandleDataCollectionRequest(dataSources []DataSource) error {
	dataCollector := NewDataCollector(dataSources)
	return dataCollector.CollectData()
}

// HandleReportGenerationRequest handles report generation requests.
func HandleReportGenerationRequest(startDate, endDate time.Time) (*SustainabilityReport, error) {
	reportingTool := NewReportingTool()
	return reportingTool.GenerateReport(startDate, endDate)
}

func main() {
	dataSources := []DataSource{
		{ID: "1", Type: "IoT", Endpoint: "http://iot-device-1/data"},
		{ID: "2", Type: "API", Endpoint: "http://api.example.com/data"},
	}

	err := HandleDataCollectionRequest(dataSources)
	if err != nil {
		log.Fatalf("Data collection failed: %v", err)
	}

	startDate := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	endDate := time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC)

	report, err := HandleReportGenerationRequest(startDate, endDate)
	if err != nil {
		log.Fatalf("Report generation failed: %v", err)
	}

	fmt.Printf("Sustainability Report: %+v\n", report)
}
