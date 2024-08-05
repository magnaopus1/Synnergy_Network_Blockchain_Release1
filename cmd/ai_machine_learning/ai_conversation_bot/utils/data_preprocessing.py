import os
import re
import yaml
import pandas as pd
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import nltk

nltk.download('punkt')
nltk.download('stopwords')

def load_config(config_path):
    """
    Load the configuration file.
    """
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
    return config

def clean_text(text, stop_words):
    """
    Clean the input text by removing special characters, stop words, and performing other preprocessing tasks.
    """
    # Convert to lowercase
    text = text.lower()
    # Remove special characters and numbers
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    # Tokenize
    words = word_tokenize(text)
    # Remove stop words
    words = [word for word in words if word not in stop_words]
    # Join words to form the cleaned text
    cleaned_text = ' '.join(words)
    return cleaned_text

def preprocess_data(data, stop_words):
    """
    Preprocess the data by cleaning the text and encoding the labels.
    """
    # Clean the text
    data['text'] = data['text'].apply(lambda x: clean_text(x, stop_words))
    
    # Encode the labels
    label_encoder = LabelEncoder()
    data['label'] = label_encoder.fit_transform(data['label'])
    
    return data, label_encoder

def save_preprocessed_data(data, save_path):
    """
    Save the preprocessed data to a CSV file.
    """
    data.to_csv(save_path, index=False)
    print(f"Preprocessed data saved to {save_path}")

def split_data(data, test_size, random_state):
    """
    Split the data into training and validation sets.
    """
    train_data, val_data = train_test_split(data, test_size=test_size, random_state=random_state)
    return train_data, val_data

def main(config_path):
    """
    Main function to load the configuration, preprocess the data, and save the preprocessed data.
    """
    # Load configuration
    config = load_config(config_path)
    
    # Load data
    data = pd.read_csv(config['input']['data_path'])
    
    # Load stop words
    stop_words = set(stopwords.words('english'))
    
    # Preprocess data
    preprocessed_data, label_encoder = preprocess_data(data, stop_words)
    
    # Save preprocessed data
    save_preprocessed_data(preprocessed_data, config['output']['preprocessed_data_path'])
    
    # Split data
    train_data, val_data = split_data(preprocessed_data, config['data_split']['test_size'], config['data_split']['random_state'])
    
    # Save split data
    save_preprocessed_data(train_data, config['output']['train_data_path'])
    save_preprocessed_data(val_data, config['output']['val_data_path'])
    
    # Save label encoder
    with open(config['output']['label_encoder_path'], 'wb') as file:
        pickle.dump(label_encoder, file)
    print(f"Label encoder saved to {config['output']['label_encoder_path']}")

if __name__ == "__main__":
    main("/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/data_preprocessing_config.yaml")
