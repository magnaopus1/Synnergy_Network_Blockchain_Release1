import os
import json
import yaml
import logging
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer, TfidfTransformer
from sklearn.pipeline import Pipeline
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
import redis
import pickle

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration
config_path = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/general_language_understanding_config.yaml'
with open(config_path, 'r') as file:
    config = yaml.safe_load(file)

class GeneralLanguageUnderstandingModel:
    def __init__(self):
        self.redis_host = config['redis']['host']
        self.redis_port = config['redis']['port']
        self.redis_password = config['redis']['password']
        self.cache = redis.Redis(
            host=self.redis_host,
            port=self.redis_port,
            password=self.redis_password
        )
        self.model = None
        self.load_model()

    def load_model(self):
        try:
            model_data = self.cache.get('general_language_understanding_model')
            if model_data:
                self.model = pickle.loads(model_data)
                logger.info("Model loaded from cache.")
            else:
                logger.info("No model found in cache.")
        except Exception as e:
            logger.error(f"Error loading model: {e}")

    def save_model(self):
        try:
            self.cache.set('general_language_understanding_model', pickle.dumps(self.model))
            logger.info("Model saved to cache.")
        except Exception as e:
            logger.error(f"Error saving model: {e}")

    def train_model(self, X, y):
        logger.info("Training model...")
        self.model = Pipeline([
            ('vect', CountVectorizer()),
            ('tfidf', TfidfTransformer()),
            ('clf', MultinomialNB())
        ])
        self.model.fit(X, y)
        self.save_model()
        logger.info("Model training complete.")

    def evaluate_model(self, X_test, y_test):
        logger.info("Evaluating model...")
        if not self.model:
            logger.error("No model found. Train the model before evaluation.")
            return

        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred)
        logger.info(f"Model accuracy: {accuracy}")
        logger.info(f"Classification report:\n{report}")
        return accuracy, report

    def predict_intent(self, text):
        if not self.model:
            logger.error("No model found. Train the model before making predictions.")
            return None
        return self.model.predict([text])[0]

    def handle_message(self, user_id, message):
        intent = self.predict_intent(message)
        return intent

if __name__ == '__main__':
    glu_model = GeneralLanguageUnderstandingModel()

    # Example data loading and preprocessing
    data_path = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/data/training_data.csv'
    data = np.genfromtxt(data_path, delimiter=',', dtype=str)
    X, y = data[:, 0], data[:, 1]

    # Split data into training and test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train and evaluate model
    glu_model.train_model(X_train, y_train)
    glu_model.evaluate_model(X_test, y_test)

    # Example usage
    user_id = "user123"
    message = "What's the weather like today?"

    intent = glu_model.handle_message(user_id, message)
    logger.info(f"Detected intent for {user_id}: {intent}")
