import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset
from sklearn.model_selection import train_test_split
import numpy as np
import pandas as pd
import os
import logging
import yaml
from collections import defaultdict

# Configuration
config_path = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/training_config.yaml'
with open(config_path, 'r') as file:
    config = yaml.safe_load(file)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Custom Dataset class
class ConversationDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_len):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = self.texts[idx]
        label = self.labels[idx]
        encoding = self.tokenizer.encode_plus(
            text,
            max_length=self.max_len,
            add_special_tokens=True,
            padding='max_length',
            return_attention_mask=True,
            return_tensors='pt',
            truncation=True
        )
        return {
            'text': text,
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'label': torch.tensor(label, dtype=torch.long)
        }

# Transformer-based conversational model
class ConversationModel(nn.Module):
    def __init__(self, vocab_size, embed_size, num_heads, hidden_dim, num_layers, num_classes, dropout):
        super(ConversationModel, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embed_size)
        encoder_layer = nn.TransformerEncoderLayer(d_model=embed_size, nhead=num_heads, dim_feedforward=hidden_dim, dropout=dropout)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.fc = nn.Linear(embed_size, num_classes)
        self.softmax = nn.LogSoftmax(dim=1)

    def forward(self, input_ids, attention_mask):
        embedded = self.embedding(input_ids)
        transformer_output = self.transformer(embedded, src_key_padding_mask=attention_mask)
        output = transformer_output.mean(dim=1)
        return self.softmax(self.fc(output))

# Adaptive learning mechanism
class AdaptiveLearning:
    def __init__(self, model, data_loader, optimizer, loss_fn, device, adaptation_rate):
        self.model = model
        self.data_loader = data_loader
        self.optimizer = optimizer
        self.loss_fn = loss_fn
        self.device = device
        self.adaptation_rate = adaptation_rate

    def adapt(self):
        self.model.train()
        for batch in self.data_loader:
            input_ids = batch['input_ids'].to(self.device)
            attention_mask = batch['attention_mask'].to(self.device)
            labels = batch['label'].to(self.device)
            
            self.optimizer.zero_grad()
            outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
            loss = self.loss_fn(outputs, labels)
            loss.backward()
            self.optimizer.step()
            
            self.adjust_learning_rate(loss.item())

    def adjust_learning_rate(self, loss):
        new_lr = self.optimizer.param_groups[0]['lr'] * (1 - self.adaptation_rate * loss)
        for param_group in self.optimizer.param_groups:
            param_group['lr'] = new_lr

# Data Loading and Preparation
def load_data(data_path, test_size, val_size, tokenizer, max_len, batch_size):
    df = pd.read_csv(data_path)
    texts = df['text'].values
    labels = df['label'].values

    train_texts, test_texts, train_labels, test_labels = train_test_split(texts, labels, test_size=test_size, random_state=42)
    train_texts, val_texts, train_labels, val_labels = train_test_split(train_texts, train_labels, test_size=val_size, random_state=42)

    train_dataset = ConversationDataset(train_texts, train_labels, tokenizer, max_len)
    val_dataset = ConversationDataset(val_texts, val_labels, tokenizer, max_len)
    test_dataset = ConversationDataset(test_texts, test_labels, tokenizer, max_len)

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

    return train_loader, val_loader, test_loader

# Training Function
def train_model(model, train_loader, val_loader, optimizer, loss_fn, device, num_epochs):
    best_accuracy = 0
    for epoch in range(num_epochs):
        model.train()
        total_loss = 0
        correct_predictions = 0
        for batch in train_loader:
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['label'].to(device)

            optimizer.zero_grad()
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            loss = loss_fn(outputs, labels)
            loss.backward()
            optimizer.step()

            total_loss += loss.item()
            _, preds = torch.max(outputs, dim=1)
            correct_predictions += torch.sum(preds == labels)

        train_accuracy = correct_predictions.double() / len(train_loader.dataset)
        train_loss = total_loss / len(train_loader)

        val_accuracy, val_loss = evaluate_model(model, val_loader, loss_fn, device)

        logger.info(f'Epoch {epoch + 1}/{num_epochs}, Train Loss: {train_loss}, Train Accuracy: {train_accuracy}')
        logger.info(f'Epoch {epoch + 1}/{num_epochs}, Val Loss: {val_loss}, Val Accuracy: {val_accuracy}')

        if val_accuracy > best_accuracy:
            best_accuracy = val_accuracy
            torch.save(model.state_dict(), config['evaluation']['save_best_model_path'])

# Evaluation Function
def evaluate_model(model, data_loader, loss_fn, device):
    model.eval()
    total_loss = 0
    correct_predictions = 0

    with torch.no_grad():
        for batch in data_loader:
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['label'].to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            loss = loss_fn(outputs, labels)

            total_loss += loss.item()
            _, preds = torch.max(outputs, dim=1)
            correct_predictions += torch.sum(preds == labels)

    accuracy = correct_predictions.double() / len(data_loader.dataset)
    loss = total_loss / len(data_loader)
    return accuracy, loss

# Main Function
def main():
    # Load configuration
    config_path = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/training_config.yaml'
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)

    # Set device
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Load tokenizer
    vocab_size = config['model']['vocab_size']
    tokenizer = ...  # Placeholder: Replace with the actual tokenizer initialization

    # Load data
    train_loader, val_loader, test_loader = load_data(
        config['data']['training_data_path'],
        config['data']['test_size'],
        config['data']['val_size'],
        tokenizer,
        config['model']['max_len'],
        config['training_params']['batch_size']
    )

    # Initialize model
    model = ConversationModel(
        vocab_size=vocab_size,
        embed_size=config['model']['embed_size'],
        num_heads=config['model']['num_heads'],
        hidden_dim=config['model']['hidden_dim'],
        num_layers=config['model']['num_layers'],
        num_classes=config['model']['num_classes'],
        dropout=config['model']['dropout']
    ).to(device)

    # Define loss function and optimizer
    loss_fn = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=config['training_params']['learning_rate'])

    # Train model
    train_model(
        model,
        train_loader,
        val_loader,
        optimizer,
        loss_fn,
        device,
        config['training_params']['num_epochs']
    )

    # Evaluate model on test data
    test_accuracy, test_loss = evaluate_model(model, test_loader, loss_fn, device)
    logger.info(f'Test Loss: {test_loss}, Test Accuracy: {test_accuracy}')

if __name__ == '__main__':
    main()
