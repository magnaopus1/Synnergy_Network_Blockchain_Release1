import os
import yaml
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder, StandardScaler
import pandas as pd
import numpy as np
import logging

# Custom Dataset for Security Model
class SecurityDataset(Dataset):
    def __init__(self, features, labels):
        self.features = features
        self.labels = labels

    def __len__(self):
        return len(self.features)

    def __getitem__(self, idx):
        return {
            'features': torch.tensor(self.features[idx], dtype=torch.float),
            'labels': torch.tensor(self.labels[idx], dtype=torch.long)
        }

# Security Model for Anomaly Detection
class AnomalyDetectionModel(nn.Module):
    def __init__(self, input_dim, hidden_dim, output_dim, dropout):
        super(AnomalyDetectionModel, self).__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout)
        self.fc2 = nn.Linear(hidden_dim, output_dim)

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.fc2(x)
        return x

def train_model(model, data_loader, criterion, optimizer, device):
    model.train()
    total_loss = 0
    correct_predictions = 0

    for batch in data_loader:
        optimizer.zero_grad()
        features = batch['features'].to(device)
        labels = batch['labels'].to(device)

        outputs = model(features)
        loss = criterion(outputs, labels)
        _, preds = torch.max(outputs, dim=1)

        loss.backward()
        optimizer.step()

        total_loss += loss.item()
        correct_predictions += torch.sum(preds == labels)

    return correct_predictions.double() / len(data_loader.dataset), total_loss / len(data_loader)

def evaluate_model(model, data_loader, criterion, device):
    model.eval()
    total_loss = 0
    correct_predictions = 0

    with torch.no_grad():
        for batch in data_loader:
            features = batch['features'].to(device)
            labels = batch['labels'].to(device)

            outputs = model(features)
            loss = criterion(outputs, labels)
            _, preds = torch.max(outputs, dim=1)

            total_loss += loss.item()
            correct_predictions += torch.sum(preds == labels)

    return correct_predictions.double() / len(data_loader.dataset), total_loss / len(data_loader)

def load_data(file_path):
    df = pd.read_csv(file_path)
    return df.drop(columns='label').values, df['label'].values

def main():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    config_path = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/security_config.yaml'
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    features, labels = load_data(config['data']['file_path'])
    scaler = StandardScaler()
    features = scaler.fit_transform(features)

    le = LabelEncoder()
    labels = le.fit_transform(labels)

    X_train, X_val, y_train, y_val = train_test_split(features, labels, test_size=0.1, random_state=config['data']['random_seed'])
    
    train_dataset = SecurityDataset(X_train, y_train)
    val_dataset = SecurityDataset(X_val, y_val)

    train_loader = DataLoader(train_dataset, batch_size=config['training_params']['batch_size'], shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=config['training_params']['batch_size'], shuffle=False)

    input_dim = X_train.shape[1]
    hidden_dim = config['model']['hidden_dim']
    output_dim = len(le.classes_)
    dropout = config['model']['dropout']

    model = AnomalyDetectionModel(input_dim, hidden_dim, output_dim, dropout).to(device)

    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=config['training_params']['learning_rate'])

    best_accuracy = 0
    patience_counter = 0

    for epoch in range(config['training_params']['num_epochs']):
        logger.info(f"Epoch {epoch + 1}/{config['training_params']['num_epochs']}")

        train_acc, train_loss = train_model(model, train_loader, criterion, optimizer, device)
        val_acc, val_loss = evaluate_model(model, val_loader, criterion, device)

        logger.info(f"Train loss: {train_loss}, Train accuracy: {train_acc}")
        logger.info(f"Validation loss: {val_loss}, Validation accuracy: {val_acc}")

        if val_acc > best_accuracy:
            best_accuracy = val_acc
            torch.save(model.state_dict(), config['evaluation']['save_best_model_path'])
            patience_counter = 0
        else:
            patience_counter += 1

        if config['training_params']['early_stopping']['enable'] and patience_counter >= config['training_params']['early_stopping']['patience']:
            logger.info("Early stopping triggered")
            break

    model.load_state_dict(torch.load(config['evaluation']['save_best_model_path']))

    test_features, test_labels = load_data(config['data']['test_file_path'])
    test_features = scaler.transform(test_features)
    test_labels = le.transform(test_labels)
    test_dataset = SecurityDataset(test_features, test_labels)
    test_loader = DataLoader(test_dataset, batch_size=config['training_params']['batch_size'], shuffle=False)

    test_acc, test_loss = evaluate_model(model, test_loader, criterion, device)
    logger.info(f"Test loss: {test_loss}, Test accuracy: {test_acc}")

    y_true = []
    y_pred = []
    model.eval()
    with torch.no_grad():
        for batch in test_loader:
            features = batch['features'].to(device)
            labels = batch['labels'].to(device)

            outputs = model(features)
            _, preds = torch.max(outputs, dim=1)

            y_true.extend(labels.cpu().numpy())
            y_pred.extend(preds.cpu().numpy())

    cm = confusion_matrix(y_true, y_pred)
    report = classification_report(y_true, y_pred, target_names=le.classes_)
    logger.info(f"Confusion Matrix:\n{cm}")
    logger.info(f"Classification Report:\n{report}")

if __name__ == '__main__':
    main()
