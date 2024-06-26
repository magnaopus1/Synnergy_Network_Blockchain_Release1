import os
import json
import yaml
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import re
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from collections import Counter

# Ensure NLTK resources are downloaded
nltk.download('punkt')
nltk.download('stopwords')

# Configuration Loader
def load_config(config_path):
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
    return config

# Text Preprocessing Function
def preprocess_text(text, stop_words):
    text = text.lower()
    text = re.sub(r'[^\w\s]', '', text)
    text = re.sub(r'\d+', '', text)
    tokens = word_tokenize(text)
    tokens = [word for word in tokens if word not in stop_words]
    return ' '.join(tokens)

# Load and Preprocess Data
def load_and_preprocess_data(data_path, stop_words):
    data = pd.read_csv(data_path)
    data['text'] = data['text'].apply(lambda x: preprocess_text(x, stop_words))
    return data

# Encode Labels
def encode_labels(data):
    label_encoder = LabelEncoder()
    data['label'] = label_encoder.fit_transform(data['label'])
    return data, label_encoder

# Split Data
def split_data(data, config):
    train_data, test_data = train_test_split(data, test_size=config['data_split']['test_size'], random_state=config['data_split']['random_state'])
    train_data, val_data = train_test_split(train_data, test_size=config['data_split']['val_size'], random_state=config['data_split']['random_state'])
    return train_data, val_data, test_data

# Save Processed Data
def save_processed_data(train_data, val_data, test_data, config):
    train_data.to_csv(config['output']['train_data_path'], index=False)
    val_data.to_csv(config['output']['val_data_path'], index=False)
    test_data.to_csv(config['output']['test_data_path'], index=False)
    print(f"Processed data saved to {config['output']['train_data_path']}, {config['output']['val_data_path']}, and {config['output']['test_data_path']}")

# Vocabulary Building
def build_vocabulary(data, config):
    counter = Counter()
    for text in data['text']:
        tokens = text.split()
        counter.update(tokens)
    vocab = {word: i for i, (word, _) in enumerate(counter.most_common(config['vocabulary']['vocab_size']))}
    vocab_path = config['vocabulary']['vocab_path']
    with open(vocab_path, 'w') as file:
        json.dump(vocab, file)
    print(f"Vocabulary saved to {vocab_path}")

# Main Execution
if __name__ == "__main__":
    config = load_config("/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/training_config.yaml")
    stop_words = set(stopwords.words('english'))
    
    data = load_and_preprocess_data(config['input']['raw_data_path'], stop_words)
    data, label_encoder = encode_labels(data)
    train_data, val_data, test_data = split_data(data, config)
    save_processed_data(train_data, val_data, test_data, config)
    build_vocabulary(data, config)
