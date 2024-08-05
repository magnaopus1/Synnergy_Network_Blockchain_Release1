package visualization_and_reporting

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"time"

	"../data_collection"
)

// Anomaly represents a detected anomaly with its details
type Anomaly struct {
	Timestamp time.Time `json:"timestamp"`
	Metric    string    `json:"metric"`
	Value     float64   `json:"value"`
	Details   string    `json:"details"`
}

// AnomalyDashboard handles the display of anomalies in an interactive dashboard
type AnomalyDashboard struct {
	TemplatePath string
	DataPath     string
}

// NewAnomalyDashboard creates a new instance of AnomalyDashboard
func NewAnomalyDashboard(templatePath, dataPath string) *AnomalyDashboard {
	return &AnomalyDashboard{
		TemplatePath: templatePath,
		DataPath:     dataPath,
	}
}

// LoadAnomalies loads anomalies from the data file
func (ad *AnomalyDashboard) LoadAnomalies() ([]Anomaly, error) {
	file, err := os.Open(ad.DataPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var anomalies []Anomaly
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&anomalies)
	if err != nil {
		return nil, err
	}
	return anomalies, nil
}

// SaveAnomalies saves anomalies to the data file
func (ad *AnomalyDashboard) SaveAnomalies(anomalies []Anomaly) error {
	file, err := os.Create(ad.DataPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(anomalies)
}

// AddAnomaly adds a new anomaly to the dashboard
func (ad *AnomalyDashboard) AddAnomaly(anomaly Anomaly) error {
	anomalies, err := ad.LoadAnomalies()
	if err != nil {
		return err
	}
	anomalies = append(anomalies, anomaly)
	return ad.SaveAnomalies(anomalies)
}

// ServeDashboard serves the anomaly dashboard web interface
func (ad *AnomalyDashboard) ServeDashboard(port int) error {
	http.HandleFunc("/", ad.dashboardHandler)
	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("Starting server at %s\n", addr)
	return http.ListenAndServe(addr, nil)
}

func (ad *AnomalyDashboard) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles(ad.TemplatePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	anomalies, err := ad.LoadAnomalies()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Title     string
		Anomalies []Anomaly
	}{
		Title:     "Anomaly Dashboard",
		Anomalies: anomalies,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// ReportAnomaly detects and reports anomalies based on metrics
func (ad *AnomalyDashboard) ReportAnomaly(collector *data_collection.NetworkMetricsCollector, threshold float64) error {
	metrics, err := collector.GetMetrics()
	if err != nil {
		return err
	}

	for _, metric := range metrics {
		if metric.Value > threshold {
			anomaly := Anomaly{
				Timestamp: metric.Timestamp,
				Metric:    metric.Type,
				Value:     metric.Value,
				Details:   fmt.Sprintf("Anomaly detected with value %f", metric.Value),
			}
			err := ad.AddAnomaly(anomaly)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
