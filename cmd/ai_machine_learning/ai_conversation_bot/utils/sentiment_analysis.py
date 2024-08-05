import yaml
import logging
from typing import Dict, Any
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix
import pandas as pd

class SentimentAnalysis:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self.load_config()
        self.setup_logging()
        self.model = self.build_model()

    def load_config(self) -> Dict:
        with open(self.config_path, 'r') as file:
            config = yaml.safe_load(file)
        return config

    def setup_logging(self):
        logging_config = self.config.get('logging', {})
        logging.basicConfig(
            filename=logging_config.get('log_file', 'sentiment_analysis.log'),
            level=logging_config.get('log_level', logging.INFO),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('SentimentAnalysis')

    def load_data(self, data_path: str):
        data = pd.read_csv(data_path)
        return data

    def preprocess_data(self, data: pd.DataFrame):
        # Implement comprehensive preprocessing steps
        # Example: Tokenization, padding, etc.
        self.logger.info("Data preprocessing started")
        # Placeholder preprocessing
        return data['text'], data['label']

    def build_model(self):
        model_config = self.config.get('model', {})
        vocab_size = model_config.get('vocab_size', 10000)
        embedding_dim = model_config.get('embedding_dim', 128)
        lstm_units = model_config.get('lstm_units', 64)
        dropout_rate = model_config.get('dropout_rate', 0.2)

        model = tf.keras.Sequential([
            tf.keras.layers.Embedding(vocab_size, embedding_dim, input_length=200),
            tf.keras.layers.LSTM(lstm_units),
            tf.keras.layers.Dropout(dropout_rate),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])

        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        self.logger.info("Model built successfully")
        return model

    def train_model(self, X_train, y_train, X_val, y_val):
        training_config = self.config.get('training', {})
        batch_size = training_config.get('batch_size', 32)
        epochs = training_config.get('epochs', 10)

        history = self.model.fit(
            X_train, y_train,
            batch_size=batch_size,
            epochs=epochs,
            validation_data=(X_val, y_val)
        )
        self.logger.info("Model training completed")
        return history

    def evaluate_model(self, X_test, y_test):
        predictions = (self.model.predict(X_test) > 0.5).astype("int32")
        accuracy = accuracy_score(y_test, predictions)
        f1 = f1_score(y_test, predictions)
        conf_matrix = confusion_matrix(y_test, predictions)

        self.logger.info(f"Model evaluation completed - Accuracy: {accuracy}, F1 Score: {f1}")
        self.logger.info(f"Confusion Matrix:\n{conf_matrix}")

    def save_model(self, model_path: str):
        self.model.save(model_path)
        self.logger.info(f"Model saved at {model_path}")

    def load_model(self, model_path: str):
        self.model = tf.keras.models.load_model(model_path)
        self.logger.info(f"Model loaded from {model_path}")

if __name__ == "__main__":
    config_file_path = "/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/sentiment_analysis_config.yaml"
    data_file_path = "/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/data/training_data.csv"
    model_save_path = "/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/models/sentiment_analysis_model.h5"

    sentiment_analysis = SentimentAnalysis(config_file_path)
    data = sentiment_analysis.load_data(data_file_path)
    X, y = sentiment_analysis.preprocess_data(data)
    X_train, X_val_test, y_train, y_val_test = train_test_split(X, y, test_size=0.2, random_state=42)
    X_val, X_test, y_val, y_test = train_test_split(X_val_test, y_val_test, test_size=0.5, random_state=42)

    sentiment_analysis.train_model(X_train, y_train, X_val, y_val)
    sentiment_analysis.evaluate_model(X_test, y_test)
    sentiment_analysis.save_model(model_save_path)
