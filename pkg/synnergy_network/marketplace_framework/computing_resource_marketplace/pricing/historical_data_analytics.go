package pricing

import (
	"errors"
	"sync"
	"time"
)

// HistoricalDataPoint represents a single data point in the historical data
type HistoricalDataPoint struct {
	Timestamp time.Time
	Price     float64
	Usage     float64
	Demand    float64
	Volatility float64
}

// HistoricalDataAnalytics manages the collection and analysis of historical data
type HistoricalDataAnalytics struct {
	mu         sync.Mutex
	data       map[string][]HistoricalDataPoint
	windowSize int
}

// NewHistoricalDataAnalytics initializes a new HistoricalDataAnalytics manager
func NewHistoricalDataAnalytics(windowSize int) *HistoricalDataAnalytics {
	return &HistoricalDataAnalytics{
		data:       make(map[string][]HistoricalDataPoint),
		windowSize: windowSize,
	}
}

// AddDataPoint adds a new data point to the historical data for a given resource
func (hda *HistoricalDataAnalytics) AddDataPoint(resourceID string, price, usage, demand, volatility float64) {
	hda.mu.Lock()
	defer hda.mu.Unlock()

	point := HistoricalDataPoint{
		Timestamp:  time.Now(),
		Price:      price,
		Usage:      usage,
		Demand:     demand,
		Volatility: volatility,
	}

	hda.data[resourceID] = append(hda.data[resourceID], point)
	if len(hda.data[resourceID]) > hda.windowSize {
		hda.data[resourceID] = hda.data[resourceID][1:]
	}
}

// GetHistoricalData retrieves the historical data for a given resource
func (hda *HistoricalDataAnalytics) GetHistoricalData(resourceID string) ([]HistoricalDataPoint, error) {
	hda.mu.Lock()
	defer hda.mu.Unlock()

	data, exists := hda.data[resourceID]
	if !exists {
		return nil, errors.New("no historical data found for the given resource ID")
	}

	return data, nil
}

// CalculateMovingAverage calculates the moving average of prices for a given resource over the historical data window
func (hda *HistoricalDataAnalytics) CalculateMovingAverage(resourceID string) (float64, error) {
	hda.mu.Lock()
	defer hda.mu.Unlock()

	data, exists := hda.data[resourceID]
	if !exists || len(data) == 0 {
		return 0, errors.New("no historical data available to calculate moving average")
	}

	sum := 0.0
	for _, point := range data {
		sum += point.Price
	}

	return sum / float64(len(data)), nil
}

// CalculateVolatility calculates the volatility of prices for a given resource over the historical data window
func (hda *HistoricalDataAnalytics) CalculateVolatility(resourceID string) (float64, error) {
	hda.mu.Lock()
	defer hda.mu.Unlock()

	data, exists := hda.data[resourceID]
	if !exists || len(data) == 0 {
		return 0, errors.New("no historical data available to calculate volatility")
	}

	mean, _ := hda.CalculateMovingAverage(resourceID)
	varianceSum := 0.0
	for _, point := range data {
		deviation := point.Price - mean
		varianceSum += deviation * deviation
	}

	variance := varianceSum / float64(len(data))
	return variance, nil
}

// CalculateTrend calculates the trend of prices for a given resource over the historical data window
func (hda *HistoricalDataAnalytics) CalculateTrend(resourceID string) (float64, error) {
	hda.mu.Lock()
	defer hda.mu.Unlock()

	data, exists := hda.data[resourceID]
	if !exists || len(data) < 2 {
		return 0, errors.New("not enough historical data to calculate trend")
	}

	start := data[0].Price
	end := data[len(data)-1].Price
	trend := (end - start) / start

	return trend, nil
}

// HistoricalDataAnalyticsManager manages historical data analytics for multiple resources
type HistoricalDataAnalyticsManager struct {
	analytics *HistoricalDataAnalytics
}

// NewHistoricalDataAnalyticsManager initializes a new HistoricalDataAnalyticsManager
func NewHistoricalDataAnalyticsManager(windowSize int) *HistoricalDataAnalyticsManager {
	return &HistoricalDataAnalyticsManager{
		analytics: NewHistoricalDataAnalytics(windowSize),
	}
}

// AddDataPoint adds a new data point for a resource
func (hdaManager *HistoricalDataAnalyticsManager) AddDataPoint(resourceID string, price, usage, demand, volatility float64) {
	hdaManager.analytics.AddDataPoint(resourceID, price, usage, demand, volatility)
}

// GetHistoricalData retrieves historical data for a resource
func (hdaManager *HistoricalDataAnalyticsManager) GetHistoricalData(resourceID string) ([]HistoricalDataPoint, error) {
	return hdaManager.analytics.GetHistoricalData(resourceID)
}

// CalculateMovingAverage calculates the moving average of prices for a resource
func (hdaManager *HistoricalDataAnalyticsManager) CalculateMovingAverage(resourceID string) (float64, error) {
	return hdaManager.analytics.CalculateMovingAverage(resourceID)
}

// CalculateVolatility calculates the volatility of prices for a resource
func (hdaManager *HistoricalDataAnalyticsManager) CalculateVolatility(resourceID string) (float64, error) {
	return hdaManager.analytics.CalculateVolatility(resourceID)
}

// CalculateTrend calculates the trend of prices for a resource
func (hdaManager *HistoricalDataAnalyticsManager) CalculateTrend(resourceID string) (float64, error) {
	return hdaManager.analytics.CalculateTrend(resourceID)
}
