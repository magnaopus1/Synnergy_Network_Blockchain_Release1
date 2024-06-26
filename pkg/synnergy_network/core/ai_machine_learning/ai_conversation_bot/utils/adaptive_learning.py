import os
import json
import yaml
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score
from collections import deque

# Configuration Loader
def load_config(config_path):
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
    return config

# Save Model
def save_model(model, model_path):
    with open(model_path, 'wb') as file:
        pickle.dump(model, file)
    print(f"Model saved to {model_path}")

# Load Model
def load_model(model_path):
    with open(model_path, 'rb') as file:
        model = pickle.load(file)
    print(f"Model loaded from {model_path}")
    return model

# Preprocess Feedback Data
def preprocess_feedback_data(feedback_data, stop_words):
    feedback_data['text'] = feedback_data['text'].apply(lambda x: preprocess_text(x, stop_words))
    return feedback_data

# Update Training Data
def update_training_data(training_data_path, feedback_data):
    current_data = pd.read_csv(training_data_path)
    updated_data = pd.concat([current_data, feedback_data], ignore_index=True)
    updated_data.to_csv(training_data_path, index=False)
    print(f"Training data updated with feedback data at {training_data_path}")

# Train Model
def train_model(data, model, config):
    X = data['text']
    y = data['label']
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=config['data_split']['val_size'], random_state=config['data_split']['random_state'])
    
    model.fit(X_train, y_train)
    y_pred = model.predict(X_val)
    
    accuracy = accuracy_score(y_val, y_pred)
    f1 = f1_score(y_val, y_pred, average='weighted')
    
    print(f"Validation Accuracy: {accuracy}")
    print(f"Validation F1 Score: {f1}")
    
    return model

# Adaptive Learning Process
def adaptive_learning_process(config):
    # Load Configurations
    training_data_path = config['input']['training_data_path']
    feedback_data_path = config['input']['feedback_data_path']
    stop_words = set(stopwords.words('english'))

    # Load and Preprocess Feedback Data
    feedback_data = pd.read_csv(feedback_data_path)
    feedback_data = preprocess_feedback_data(feedback_data, stop_words)
    
    # Update Training Data
    update_training_data(training_data_path, feedback_data)
    
    # Load Updated Training Data
    training_data = pd.read_csv(training_data_path)
    
    # Load Model
    model = load_model(config['model']['path'])
    
    # Train Model with Updated Data
    model = train_model(training_data, model, config)
    
    # Save Updated Model
    save_model(model, config['model']['path'])

# Main Execution
if __name__ == "__main__":
    config = load_config("/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/adaptive_learning_config.yaml")
    adaptive_learning_process(config)
