package analytics

import (
    "bytes"
    "image"
    "image/color"
    "image/png"
    "log"
    "os"

    "github.com/wcharczuk/go-chart/v2" // go-chart is a library for chart rendering
)

// VisualizationConfig defines the configuration for generating charts
type VisualizationConfig struct {
    Title      string
    Values     []float64
    Categories []string
    OutputPath string
}

// GenerateBarChart generates a bar chart from the provided configuration
func GenerateBarChart(config VisualizationConfig) error {
    bars := make([]chart.Value, len(config.Values))
    for i, value := range config.Values {
        bars[i] = chart.Value{
            Value: value,
            Label: config.Categories[i],
        }
    }

    barChart := chart.BarChart{
        Title:      config.Title,
        Background: chart.Style{Padding: chart.Box{Top: 20, Left: 20, Right: 20, Bottom: 20}},
        Bars:       bars,
    }

    buffer := bytes.NewBuffer([]byte{})
    err := barChart.Render(chart.PNG, buffer)
    if err != nil {
        log.Printf("Failed to render bar chart: %v", err)
        return err
    }

    return saveImage(buffer, config.OutputPath)
}

// GeneratePieChart generates a pie chart from the provided configuration
func GeneratePieChart(config VisualizationConfig) error {
    values := make([]chart.Value, len(config.Values))
    for i, value := range config.Values {
        values[i] = chart.Value{
            Value: value,
            Label: config.Categories[i],
        }
    }

    pieChart := chart.PieChart{
        Title:  config.Title,
        Values: values,
    }

    buffer := bytes.NewBuffer([]byte{})
    err := pieChart.Render(chart.PNG, buffer)
    if err != nil {
        log.Printf("Failed to render pie chart: %v", err)
        return err
    }

    return saveImage(buffer, config.OutputPath)
}

// saveImage saves a rendered image buffer to a file
func saveImage(buf *bytes.Buffer, path string) error {
    img, _, err := image.Decode(buf)
    if err != nil {
        log.Printf("Failed to decode image: %v", err)
        return err
    }

    outFile, err := os.Create(path)
    if err != nil {
        log.Printf("Failed to create file: %v", err)
        return err
    }
    defer outFile.Close()

    png.Encode(outFile, img)
    log.Printf("Chart saved to %s", path)
    return nil
}

// main function to initiate visualization module
func main() {
    // Example data setup
    barConfig := VisualizationConfig{
        Title:      "Sample Bar Chart",
        Values:     []float64{5, 10, 15, 20},
        Categories: []string{"Q1", "Q2", "Q3", "Q4"},
        OutputPath: "output/bar_chart.png",
    }
    pieConfig := VisualizationConfig{
        Title:      "Sample Pie Chart",
        Values:     []float64{5, 10, 15, 20},
        Categories: []string{"East", "West", "South", "North"},
        OutputPath: "output/pie_chart.png",
    }

    if err := GenerateBarChart(barConfig); err != nil {
        log.Println("Error generating bar chart:", err)
    }
    if err := GeneratePieChart(pieConfig); err != nil {
        log.Println("Error generating pie chart:", err)
    }
}
