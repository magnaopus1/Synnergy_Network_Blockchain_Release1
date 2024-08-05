import os
import json
import yaml
import random
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from datetime import datetime
from tqdm import tqdm

# Configuration Loader
def load_config(config_path):
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
    return config

# Custom Dataset Class
class CustomDataset(Dataset):
    def __init__(self, data_path):
        self.data = []
        with open(data_path, 'r') as file:
            for line in file:
                self.data.append(json.loads(line))
        self.data = self.process_data(self.data)

    def process_data(self, data):
        processed = []
        for item in data:
            text = item['text']
            label = item['label']
            processed.append((text, label))
        return processed

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        return self.data[idx]

# Custom Neural Network Model
class CustomModel(nn.Module):
    def __init__(self, config):
        super(CustomModel, self).__init__()
        self.embedding = nn.Embedding(config['vocab_size'], config['embedding_dim'])
        self.lstm = nn.LSTM(config['embedding_dim'], config['hidden_dim'], batch_first=True)
        self.fc = nn.Linear(config['hidden_dim'], config['output_dim'])
        self.softmax = nn.Softmax(dim=1)

    def forward(self, x):
        x = self.embedding(x)
        x, _ = self.lstm(x)
        x = self.fc(x[:, -1, :])
        return self.softmax(x)

# Training Function
def train_model(config):
    # Load Data
    dataset = CustomDataset(config['data']['training_data_path'])
    train_data, val_data = train_test_split(dataset, test_size=config['data']['validation_split'])
    train_loader = DataLoader(train_data, batch_size=config['training']['batch_size'], shuffle=True)
    val_loader = DataLoader(val_data, batch_size=config['training']['batch_size'], shuffle=False)

    # Initialize Model
    model = CustomModel(config['model'])
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=config['training']['learning_rate'])

    # Training Loop
    best_val_loss = float('inf')
    for epoch in range(config['training']['epochs']):
        model.train()
        train_loss = 0
        for texts, labels in tqdm(train_loader, desc=f"Training Epoch {epoch + 1}/{config['training']['epochs']}"):
            texts = torch.tensor(texts)
            labels = torch.tensor(labels)

            optimizer.zero_grad()
            outputs = model(texts)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()

            train_loss += loss.item()

        val_loss = validate_model(model, val_loader, criterion)
        print(f"Epoch {epoch + 1}, Train Loss: {train_loss / len(train_loader)}, Validation Loss: {val_loss}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            save_model(model, config['model_storage']['path'], config['model_storage']['model_name'])

# Validation Function
def validate_model(model, val_loader, criterion):
    model.eval()
    val_loss = 0
    with torch.no_grad():
        for texts, labels in tqdm(val_loader, desc="Validating"):
            texts = torch.tensor(texts)
            labels = torch.tensor(labels)
            outputs = model(texts)
            loss = criterion(outputs, labels)
            val_loss += loss.item()
    return val_loss / len(val_loader)

# Save Model Function
def save_model(model, path, model_name):
    os.makedirs(path, exist_ok=True)
    model_path = os.path.join(path, f"{model_name}.pth")
    torch.save(model.state_dict(), model_path)
    print(f"Model saved to {model_path}")

# Main Execution
if __name__ == "__main__":
    config = load_config("/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/training_config.yaml")
    train_model(config)
