import os
import yaml
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
import pandas as pd
import numpy as np
import logging

class SentimentAnalysisDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_length):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = self.labels[idx]
        encoding = self.tokenizer.encode_plus(
            text,
            add_special_tokens=True,
            max_length=self.max_length,
            return_token_type_ids=False,
            padding='max_length',
            return_attention_mask=True,
            return_tensors='pt',
            truncation=True
        )
        return {
            'text': text,
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }

class SentimentClassifier(nn.Module):
    def __init__(self, vocab_size, embed_dim, hidden_dim, output_dim, n_layers, bidirectional, dropout):
        super(SentimentClassifier, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.rnn = nn.LSTM(embed_dim, hidden_dim, num_layers=n_layers, bidirectional=bidirectional, dropout=dropout, batch_first=True)
        self.fc = nn.Linear(hidden_dim * 2 if bidirectional else hidden_dim, output_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, input_ids, attention_mask):
        embedded = self.dropout(self.embedding(input_ids))
        packed_output, (hidden, cell) = self.rnn(embedded)
        if self.rnn.bidirectional:
            hidden = self.dropout(torch.cat((hidden[-2, :, :], hidden[-1, :, :]), dim=1))
        else:
            hidden = self.dropout(hidden[-1, :, :])
        output = self.fc(hidden)
        return output

def train_model(model, data_loader, criterion, optimizer, device):
    model = model.train()
    total_loss = 0
    correct_predictions = 0

    for batch in data_loader:
        optimizer.zero_grad()
        input_ids = batch['input_ids'].to(device)
        attention_mask = batch['attention_mask'].to(device)
        labels = batch['labels'].to(device)

        outputs = model(input_ids, attention_mask)
        loss = criterion(outputs, labels)
        _, preds = torch.max(outputs, dim=1)

        loss.backward()
        optimizer.step()

        total_loss += loss.item()
        correct_predictions += torch.sum(preds == labels)

    return correct_predictions.double() / len(data_loader.dataset), total_loss / len(data_loader)

def evaluate_model(model, data_loader, criterion, device):
    model = model.eval()
    total_loss = 0
    correct_predictions = 0

    with torch.no_grad():
        for batch in data_loader:
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['labels'].to(device)

            outputs = model(input_ids, attention_mask)
            loss = criterion(outputs, labels)
            _, preds = torch.max(outputs, dim=1)

            total_loss += loss.item()
            correct_predictions += torch.sum(preds == labels)

    return correct_predictions.double() / len(data_loader.dataset), total_loss / len(data_loader)

def load_data(file_path):
    df = pd.read_csv(file_path)
    return df['text'].values, df['label'].values

def main():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    config_path = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/training_config.yaml'
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    texts, labels = load_data(config['data']['file_path'])
    tokenizer = torch.load(config['model']['tokenizer_path'])
    max_length = config['model']['max_length']

    le = LabelEncoder()
    labels = le.fit_transform(labels)

    X_train, X_val, y_train, y_val = train_test_split(texts, labels, test_size=0.1, random_state=config['data']['random_seed'])
    
    train_dataset = SentimentAnalysisDataset(X_train, y_train, tokenizer, max_length)
    val_dataset = SentimentAnalysisDataset(X_val, y_val, tokenizer, max_length)

    train_loader = DataLoader(train_dataset, batch_size=config['training_params']['batch_size'], shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=config['training_params']['batch_size'], shuffle=False)

    vocab_size = tokenizer.vocab_size
    embed_dim = config['model']['embed_dim']
    hidden_dim = config['model']['hidden_dim']
    output_dim = len(le.classes_)
    n_layers = config['model']['n_layers']
    bidirectional = config['model']['bidirectional']
    dropout = config['model']['dropout']

    model = SentimentClassifier(vocab_size, embed_dim, hidden_dim, output_dim, n_layers, bidirectional, dropout).to(device)

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

    test_texts, test_labels = load_data(config['data']['test_file_path'])
    test_labels = le.transform(test_labels)
    test_dataset = SentimentAnalysisDataset(test_texts, test_labels, tokenizer, max_length)
    test_loader = DataLoader(test_dataset, batch_size=config['training_params']['batch_size'], shuffle=False)

    test_acc, test_loss = evaluate_model(model, test_loader, criterion, device)
    logger.info(f"Test loss: {test_loss}, Test accuracy: {test_acc}")

    y_true = []
    y_pred = []
    model.eval()
    with torch.no_grad():
        for batch in test_loader:
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['labels'].to(device)

            outputs = model(input_ids, attention_mask)
            _, preds = torch.max(outputs, dim=1)

            y_true.extend(labels.cpu().numpy())
            y_pred.extend(preds.cpu().numpy())

    report = classification_report(y_true, y_pred, target_names=le.classes_)
    logger.info(f"Classification Report:\n{report}")

if __name__ == '__main__':
    main()
