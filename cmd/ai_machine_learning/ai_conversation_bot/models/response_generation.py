import os
import yaml
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import pandas as pd
import numpy as np
import logging

# Custom Dataset for Response Generation Model
class ResponseDataset(Dataset):
    def __init__(self, inputs, outputs):
        self.inputs = inputs
        self.outputs = outputs

    def __len__(self):
        return len(self.inputs)

    def __getitem__(self, idx):
        return {
            'inputs': torch.tensor(self.inputs[idx], dtype=torch.long),
            'outputs': torch.tensor(self.outputs[idx], dtype=torch.long)
        }

# Transformer-based Generative Model
class TransformerModel(nn.Module):
    def __init__(self, vocab_size, embed_size, num_heads, num_layers, hidden_dim, dropout):
        super(TransformerModel, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embed_size)
        self.transformer = nn.Transformer(embed_size, num_heads, num_layers, num_layers, hidden_dim, dropout=dropout)
        self.fc_out = nn.Linear(embed_size, vocab_size)
        self.dropout = nn.Dropout(dropout)

    def forward(self, src, tgt):
        src = self.embedding(src)
        tgt = self.embedding(tgt)
        output = self.transformer(src, tgt)
        output = self.fc_out(output)
        return output

def train_model(model, data_loader, criterion, optimizer, device):
    model.train()
    total_loss = 0

    for batch in data_loader:
        optimizer.zero_grad()
        inputs = batch['inputs'].to(device)
        outputs = batch['outputs'].to(device)

        predictions = model(inputs, outputs[:, :-1])
        loss = criterion(predictions.reshape(-1, predictions.shape[-1]), outputs[:, 1:].reshape(-1))
        loss.backward()
        optimizer.step()

        total_loss += loss.item()

    return total_loss / len(data_loader)

def evaluate_model(model, data_loader, criterion, device):
    model.eval()
    total_loss = 0

    with torch.no_grad():
        for batch in data_loader:
            inputs = batch['inputs'].to(device)
            outputs = batch['outputs'].to(device)

            predictions = model(inputs, outputs[:, :-1])
            loss = criterion(predictions.reshape(-1, predictions.shape[-1]), outputs[:, 1:].reshape(-1))

            total_loss += loss.item()

    return total_loss / len(data_loader)

def load_data(file_path):
    df = pd.read_csv(file_path)
    inputs = df['input_text'].apply(lambda x: list(map(int, x.split()))).tolist()
    outputs = df['output_text'].apply(lambda x: list(map(int, x.split()))).tolist()
    return inputs, outputs

def main():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    config_path = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/conversation_bot_config.yaml'
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    inputs, outputs = load_data(config['data']['file_path'])
    vocab_size = config['model']['vocab_size']

    X_train, X_val, y_train, y_val = train_test_split(inputs, outputs, test_size=0.1, random_state=config['data']['random_seed'])
    
    train_dataset = ResponseDataset(X_train, y_train)
    val_dataset = ResponseDataset(X_val, y_val)

    train_loader = DataLoader(train_dataset, batch_size=config['training_params']['batch_size'], shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=config['training_params']['batch_size'], shuffle=False)

    model = TransformerModel(
        vocab_size=vocab_size,
        embed_size=config['model']['embed_size'],
        num_heads=config['model']['num_heads'],
        num_layers=config['model']['num_layers'],
        hidden_dim=config['model']['hidden_dim'],
        dropout=config['model']['dropout']
    ).to(device)

    criterion = nn.CrossEntropyLoss(ignore_index=config['data']['pad_token_id'])
    optimizer = optim.Adam(model.parameters(), lr=config['training_params']['learning_rate'])

    best_loss = float('inf')
    patience_counter = 0

    for epoch in range(config['training_params']['num_epochs']):
        logger.info(f"Epoch {epoch + 1}/{config['training_params']['num_epochs']}")

        train_loss = train_model(model, train_loader, criterion, optimizer, device)
        val_loss = evaluate_model(model, val_loader, criterion, device)

        logger.info(f"Train loss: {train_loss}")
        logger.info(f"Validation loss: {val_loss}")

        if val_loss < best_loss:
            best_loss = val_loss
            torch.save(model.state_dict(), config['evaluation']['save_best_model_path'])
            patience_counter = 0
        else:
            patience_counter += 1

        if config['training_params']['early_stopping']['enable'] and patience_counter >= config['training_params']['early_stopping']['patience']:
            logger.info("Early stopping triggered")
            break

    model.load_state_dict(torch.load(config['evaluation']['save_best_model_path']))

    test_inputs, test_outputs = load_data(config['data']['test_file_path'])
    test_dataset = ResponseDataset(test_inputs, test_outputs)
    test_loader = DataLoader(test_dataset, batch_size=config['training_params']['batch_size'], shuffle=False)

    test_loss = evaluate_model(model, test_loader, criterion, device)
    logger.info(f"Test loss: {test_loss}")

if __name__ == '__main__':
    main()
