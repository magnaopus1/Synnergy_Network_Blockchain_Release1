// Package reporting_and_visualization provides tools for reporting and visualizing smart contract audits.
package reporting_and_visualization

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/synnergy_network/core/crypto"
	"github.com/synnergy_network/core/models"
	"github.com/synnergy_network/core/utils"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"
)

// VisualizationTool defines the structure for visualization tools used in smart contract auditing.
type VisualizationTool struct {
	AuditResults []models.AuditResult
	OutputPath   string
}

// NewVisualizationTool initializes a new VisualizationTool.
func NewVisualizationTool(outputPath string) *VisualizationTool {
	return &VisualizationTool{
		AuditResults: []models.AuditResult{},
		OutputPath:   outputPath,
	}
}

// AddAuditResult adds an audit result to the visualization tool.
func (vt *VisualizationTool) AddAuditResult(result models.AuditResult) {
	vt.AuditResults = append(vt.AuditResults, result)
}

// GenerateVulnerabilityChart generates a bar chart for the number of vulnerabilities found in each audit.
func (vt *VisualizationTool) GenerateVulnerabilityChart() error {
	log.Println("Generating vulnerability chart...")

	if len(vt.AuditResults) == 0 {
		return fmt.Errorf("no audit results to visualize")
	}

	// Create a new plot
	p, err := plot.New()
	if err != nil {
		return fmt.Errorf("error creating plot: %v", err)
	}

	p.Title.Text = "Vulnerabilities Found in Smart Contracts"
	p.X.Label.Text = "Smart Contracts"
	p.Y.Label.Text = "Number of Vulnerabilities"

	// Create the bar chart
	values := make(plotter.Values, len(vt.AuditResults))
	labels := make([]string, len(vt.AuditResults))
	for i, result := range vt.AuditResults {
		values[i] = float64(len(result.Vulnerabilities))
		labels[i] = result.ContractName
	}

	bars, err := plotter.NewBarChart(values, vg.Points(20))
	if err != nil {
		return fmt.Errorf("error creating bar chart: %v", err)
	}

	p.Add(bars)
	p.NominalX(labels...)

	// Save the plot to a PNG file
	if err := p.Save(10*vg.Inch, 5*vg.Inch, fmt.Sprintf("%s/vulnerability_chart.png", vt.OutputPath)); err != nil {
		return fmt.Errorf("error saving plot: %v", err)
	}

	log.Println("Vulnerability chart generated successfully.")
	return nil
}

// GenerateRecommendationChart generates a pie chart for the types of recommendations made in the audits.
func (vt *VisualizationTool) GenerateRecommendationChart() error {
	log.Println("Generating recommendation chart...")

	if len(vt.AuditResults) == 0 {
		return fmt.Errorf("no audit results to visualize")
	}

	// Create a new plot
	p, err := plot.New()
	if err != nil {
		return fmt.Errorf("error creating plot: %v", err)
	}

	p.Title.Text = "Types of Recommendations"

	// Aggregate recommendation data
	recommendationMap := make(map[string]int)
	for _, result := range vt.AuditResults {
		for _, recommendation := range result.Recommendations {
			recommendationMap[recommendation]++
		}
	}

	values := make(plotter.Values, len(recommendationMap))
	labels := make([]string, len(recommendationMap))
	i := 0
	for label, value := range recommendationMap {
		values[i] = float64(value)
		labels[i] = label
		i++
	}

	// Create the pie chart
	pie, err := plotter.NewPieChart(values)
	if err != nil {
		return fmt.Errorf("error creating pie chart: %v", err)
	}

	pie.NominalX(labels...)
	p.Add(pie)

	// Save the plot to a PNG file
	if err := p.Save(10*vg.Inch, 5*vg.Inch, fmt.Sprintf("%s/recommendation_chart.png", vt.OutputPath)); err != nil {
		return fmt.Errorf("error saving plot: %v", err)
	}

	log.Println("Recommendation chart generated successfully.")
	return nil
}

// GenerateTimeSeriesChart generates a time series chart for the audit results over time.
func (vt *VisualizationTool) GenerateTimeSeriesChart() error {
	log.Println("Generating time series chart...")

	if len(vt.AuditResults) == 0 {
		return fmt.Errorf("no audit results to visualize")
	}

	// Create a new plot
	p, err := plot.New()
	if err != nil {
		return fmt.Errorf("error creating plot: %v", err)
	}

	p.Title.Text = "Audit Results Over Time"
	p.X.Label.Text = "Time"
	p.Y.Label.Text = "Number of Vulnerabilities"

	// Prepare time series data
	pts := make(plotter.XYs, len(vt.AuditResults))
	for i, result := range vt.AuditResults {
		pts[i].X = float64(result.AuditTimestamp.Unix())
		pts[i].Y = float64(len(result.Vulnerabilities))
	}

	// Create the line chart
	line, points, err := plotter.NewLinePoints(pts)
	if err != nil {
		return fmt.Errorf("error creating line chart: %v", err)
	}

	p.Add(line, points)
	line.Color = plotutil.Color(1)
	points.Shape = plotutil.Shape(1)

	// Save the plot to a PNG file
	if err := p.Save(10*vg.Inch, 5*vg.Inch, fmt.Sprintf("%s/timeseries_chart.png", vt.OutputPath)); err != nil {
		return fmt.Errorf("error saving plot: %v", err)
	}

	log.Println("Time series chart generated successfully.")
	return nil
}

// EncryptVisualization encrypts the generated visualization files using the provided key.
func (vt *VisualizationTool) EncryptVisualization(key string) error {
	log.Println("Encrypting visualization files...")

	files, err := os.ReadDir(vt.OutputPath)
	if err != nil {
		return fmt.Errorf("error reading output directory: %v", err)
	}

	for _, file := range files {
		if !file.IsDir() && (file.Name() == "vulnerability_chart.png" || file.Name() == "recommendation_chart.png" || file.Name() == "timeseries_chart.png") {
			filePath := fmt.Sprintf("%s/%s", vt.OutputPath, file.Name())
			content, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("error reading file: %v", err)
			}

			encryptedContent, err := crypto.EncryptAES(content, key)
			if err != nil {
				return fmt.Errorf("error encrypting file: %v", err)
			}

			err = os.WriteFile(filePath, encryptedContent, 0644)
			if err != nil {
				return fmt.Errorf("error writing encrypted file: %v", err)
			}
		}
	}

	log.Println("Visualization files encrypted successfully.")
	return nil
}

// DecryptVisualization decrypts the generated visualization files using the provided key.
func (vt *VisualizationTool) DecryptVisualization(key string) error {
	log.Println("Decrypting visualization files...")

	files, err := os.ReadDir(vt.OutputPath)
	if err != nil {
		return fmt.Errorf("error reading output directory: %v", err)
	}

	for _, file := range files {
		if !file.IsDir() && (file.Name() == "vulnerability_chart.png" || file.Name() == "recommendation_chart.png" || file.Name() == "timeseries_chart.png") {
			filePath := fmt.Sprintf("%s/%s", vt.OutputPath, file.Name())
			encryptedContent, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("error reading file: %v", err)
			}

			decryptedContent, err := crypto.DecryptAES(encryptedContent, key)
			if err != nil {
				return fmt.Errorf("error decrypting file: %v", err)
			}

			err = os.WriteFile(filePath, decryptedContent, 0644)
			if err != nil {
				return fmt.Errorf("error writing decrypted file: %v", err)
			}
		}
	}

	log.Println("Visualization files decrypted successfully.")
	return nil
}
