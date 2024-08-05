package ai_algorithms

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"math"
	"math/rand"
	"os"

	"golang.org/x/crypto/scrypt"
	"gonum.org/v1/gonum/mat"
)

// UnsupervisedModel represents an unsupervised learning model for anomaly detection
type UnsupervisedModel struct {
	Centroids     *mat.Dense
	Threshold     float64
	EncryptionKey []byte
}

// TrainUnsupervisedModel trains the model using the provided dataset without labels
func (m *UnsupervisedModel) TrainUnsupervisedModel(data *mat.Dense, k int) error {
	// Validate data
	r, c := data.Dims()
	if r == 0 || c == 0 {
		return errors.New("empty dataset")
	}

	// Initialize centroids randomly
	m.Centroids = mat.NewDense(k, c, nil)
	for i := 0; i < k; i++ {
		for j := 0; j < c; j++ {
			m.Centroids.Set(i, j, data.At(rand.Intn(r), j))
		}
	}

	// Run k-means clustering to find centroids
	for i := 0; i < 100; i++ {
		clusters := make([][]float64, k)
		for i := 0; i < k; i++ {
			clusters[i] = []float64{}
		}

		for i := 0; i < r; i++ {
			row := mat.Row(nil, i, data)
			closest := m.closestCentroid(row)
			clusters[closest] = append(clusters[closest], row...)
		}

		for i := 0; i < k; i++ {
			cluster := mat.NewDense(len(clusters[i])/c, c, clusters[i])
			for j := 0; j < c; j++ {
				mean := mat.Sum(cluster.ColView(j)) / float64(cluster.RawMatrix().Rows)
				m.Centroids.Set(i, j, mean)
			}
		}
	}

	// Calculate threshold for anomaly detection
	m.Threshold = m.calculateThreshold(data)

	return nil
}

// closestCentroid finds the index of the closest centroid to the given data point
func (m *UnsupervisedModel) closestCentroid(data []float64) int {
	minDist := math.MaxFloat64
	closest := -1
	for i := 0; i < m.Centroids.RawMatrix().Rows; i++ {
		centroid := mat.Row(nil, i, m.Centroids)
		dist := euclideanDistance(data, centroid)
		if dist < minDist {
			minDist = dist
			closest = i
		}
	}
	return closest
}

// euclideanDistance calculates the Euclidean distance between two points
func euclideanDistance(a, b []float64) float64 {
	sum := 0.0
	for i := range a {
		sum += math.Pow(a[i]-b[i], 2)
	}
	return math.Sqrt(sum)
}

// DetectAnomalies detects anomalies based on the distance to the nearest centroid
func (m *UnsupervisedModel) DetectAnomalies(data *mat.Dense) ([]bool, error) {
	// Validate model
	if m.Centroids == nil {
		return nil, errors.New("model is not trained")
	}

	r, _ := data.Dims()
	anomalies := make([]bool, r)
	for i := 0; i < r; i++ {
		row := mat.Row(nil, i, data)
		closest := m.closestCentroid(row)
		centroid := mat.Row(nil, closest, m.Centroids)
		dist := euclideanDistance(row, centroid)
		anomalies[i] = dist > m.Threshold
	}

	return anomalies, nil
}

// SaveModel saves the model to a file
func (m *UnsupervisedModel) SaveModel(filepath string) error {
	data, err := m.Centroids.MarshalBinary()
	if err != nil {
		return err
	}
	encryptedData, err := encrypt(data, m.EncryptionKey)
	if err != nil {
		return err
	}
	modelData := map[string]interface{}{
		"centroids": encryptedData,
		"threshold": m.Threshold,
	}
	encodedData, err := json.Marshal(modelData)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath, encodedData, 0644)
}

// LoadModel loads the model from a file
func (m *UnsupervisedModel) LoadModel(filepath string) error {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}
	var modelData map[string]interface{}
	err = json.Unmarshal(data, &modelData)
	if err != nil {
		return err
	}

	encryptedCentroids := modelData["centroids"].([]byte)
	decryptedData, err := decrypt(encryptedCentroids, m.EncryptionKey)
	if err != nil {
		return err
	}
	m.Centroids = mat.NewDense(len(decryptedData)/8, 8, decryptedData)
	m.Threshold = modelData["threshold"].(float64)

	return nil
}

// deriveKey derives a key using scrypt
func deriveKey(password []byte) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	key, err := scrypt.Key(password, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// encrypt encrypts data using AES
func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES
func decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// calculateThreshold calculates a threshold based on training data
func (m *UnsupervisedModel) calculateThreshold(data *mat.Dense) float64 {
	threshold := 0.0
	r, _ := data.Dims()
	for i := 0; i < r; i++ {
		row := mat.Row(nil, i, data)
		closest := m.closestCentroid(row)
		centroid := mat.Row(nil, closest, m.Centroids)
		dist := euclideanDistance(row, centroid)
		if dist > threshold {
			threshold = dist
		}
	}
	return threshold
}
