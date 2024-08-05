package ai_algorithms

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/gonum/stat"
	"golang.org/x/crypto/scrypt"
)

// SupervisedModel represents a supervised learning model for anomaly detection
type SupervisedModel struct {
	Weights       *mat.Dense
	Threshold     float64
	EncryptionKey []byte
	LabelMap      map[string]int
}

// TrainSupervisedModel trains the model using the provided labeled dataset
func (m *SupervisedModel) TrainSupervisedModel(data *mat.Dense, labels []int) error {
	// Validate data and labels
	r, c := data.Dims()
	if r == 0 || c == 0 {
		return errors.New("empty dataset")
	}
	if len(labels) != r {
		return errors.New("labels length does not match dataset rows")
	}

	// Calculate the mean and covariance matrix for each class
	classData := make(map[int]*mat.Dense)
	for i := 0; i < r; i++ {
		class := labels[i]
		if classData[class] == nil {
			classData[class] = mat.NewDense(0, c, nil)
		}
		classData[class].Stack(classData[class], data.RowView(i))
	}

	// Initialize weights randomly for each class
	m.Weights = mat.NewDense(len(classData), c, nil)
	for class, classMatrix := range classData {
		mean := stat.Mean(classMatrix.RawMatrix().Data, nil)
		covariance := mat.NewSymDense(c, nil)
		stat.CovarianceMatrix(covariance, classMatrix, nil)
		for j := 0; j < c; j++ {
			m.Weights.Set(class, j, mean + 2*mat.Sum(covariance))
		}
	}

	// Define a threshold for anomaly detection
	m.Threshold = calculateThreshold(classData, m.Weights)

	return nil
}

// Predict predicts the class of the input data
func (m *SupervisedModel) Predict(data *mat.Dense) ([]int, error) {
	// Validate model
	if m.Weights == nil {
		return nil, errors.New("model is not trained")
	}

	r, _ := data.Dims()
	predictions := make([]int, r)
	for i := 0; i < r; i++ {
		row := mat.Row(nil, i, data)
		maxScore := -1.0
		bestClass := -1
		for class := 0; class < m.Weights.Dims(); class++ {
			score := mat.Dot(mat.NewVecDense(len(row), row), mat.NewVecDense(len(row), m.Weights.RawRowView(class)))
			if score > maxScore {
				maxScore = score
				bestClass = class
			}
		}
		predictions[i] = bestClass
	}

	return predictions, nil
}

// DetectAnomalies detects anomalies based on the threshold
func (m *SupervisedModel) DetectAnomalies(data *mat.Dense) ([]bool, error) {
	// Validate model
	if m.Weights == nil {
		return nil, errors.New("model is not trained")
	}

	r, _ := data.Dims()
	anomalies := make([]bool, r)
	for i := 0; i < r; i++ {
		row := mat.Row(nil, i, data)
		maxScore := -1.0
		for class := 0; class < m.Weights.Dims(); class++ {
			score := mat.Dot(mat.NewVecDense(len(row), row), mat.NewVecDense(len(row), m.Weights.RawRowView(class)))
			if score > maxScore {
				maxScore = score
			}
		}
		anomalies[i] = maxScore > m.Threshold
	}

	return anomalies, nil
}

// SaveModel saves the model to a file
func (m *SupervisedModel) SaveModel(filepath string) error {
	data, err := m.Weights.MarshalBinary()
	if err != nil {
		return err
	}
	encryptedData, err := encrypt(data, m.EncryptionKey)
	if err != nil {
		return err
	}
	modelData := map[string]interface{}{
		"weights":    encryptedData,
		"threshold":  m.Threshold,
		"label_map":  m.LabelMap,
	}
	encodedData, err := json.Marshal(modelData)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath, encodedData, 0644)
}

// LoadModel loads the model from a file
func (m *SupervisedModel) LoadModel(filepath string) error {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}
	var modelData map[string]interface{}
	err = json.Unmarshal(data, &modelData)
	if err != nil {
		return err
	}

	encryptedWeights := modelData["weights"].([]byte)
	decryptedData, err := decrypt(encryptedWeights, m.EncryptionKey)
	if err != nil {
		return err
	}
	m.Weights = mat.NewDense(len(decryptedData)/8, 8, decryptedData)
	m.Threshold = modelData["threshold"].(float64)
	m.LabelMap = modelData["label_map"].(map[string]int)

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
func calculateThreshold(classData map[int]*mat.Dense, weights *mat.Dense) float64 {
	threshold := 0.0
	for class, data := range classData {
		r, _ := data.Dims()
		for i := 0; i < r; i++ {
			row := mat.Row(nil, i, data)
			score := mat.Dot(mat.NewVecDense(len(row), row), mat.NewVecDense(len(row), weights.RawRowView(class)))
			if score > threshold {
				threshold = score
			}
		}
	}
	return threshold
}
