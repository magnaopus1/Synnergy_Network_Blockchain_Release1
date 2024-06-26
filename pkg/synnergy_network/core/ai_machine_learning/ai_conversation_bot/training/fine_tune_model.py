import os
import yaml
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset, random_split
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score
import pandas as pd
import numpy as np
import logging

# Load configuration
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
        inputs = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_len,
            return_tensors='pt'
        )
        return {
            'input_ids': inputs['input_ids'].flatten(),
            'attention_mask': inputs['attention_mask'].flatten(),
            'label': torch.tensor(label, dtype=torch.long)
        }

# Model definition
class ConversationModel(nn.Module):
    def __init__(self, vocab_size, embed_size, num_heads, hidden_dim, num_layers, num_classes, dropout):
        super(ConversationModel, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embed_size)
        encoder_layers = nn.TransformerEncoderLayer(d_model=embed_size, nhead=num_heads, dim_feedforward=hidden_dim, dropout=dropout)
        self.transformer_encoder = nn.TransformerEncoder(encoder_layers, num_layers)
        self.fc = nn.Linear(embed_size, num_classes)
        self.dropout = nn.Dropout(dropout)

    def forward(self, input_ids, attention_mask):
        embedded = self.embedding(input_ids) * attention_mask.unsqueeze(-1)
        transformer_output = self.transformer_encoder(embedded.permute(1, 0, 2))
        pooled_output = transformer_output.mean(dim=0)
        output = self.fc(self.dropout(pooled_output))
        return output

# Function to train model
def train_model(model, dataloaders, criterion, optimizer, scheduler, num_epochs, device):
    best_model_wts = model.state_dict()
    best_acc = 0.0

    for epoch in range(num_epochs):
        logger.info(f'Epoch {epoch}/{num_epochs - 1}')
        logger.info('-' * 10)

        for phase in ['train', 'val']:
            if phase == 'train':
                model.train()
            else:
                model.eval()

            running_loss = 0.0
            running_corrects = 0

            for batch in dataloaders[phase]:
                inputs = batch['input_ids'].to(device)
                masks = batch['attention_mask'].to(device)
                labels = batch['label'].to(device)

                optimizer.zero_grad()

                with torch.set_grad_enabled(phase == 'train'):
                    outputs = model(inputs, masks)
                    _, preds = torch.max(outputs, 1)
                    loss = criterion(outputs, labels)

                    if phase == 'train':
                        loss.backward()
                        optimizer.step()

                running_loss += loss.item() * inputs.size(0)
                running_corrects += torch.sum(preds == labels.data)

            if phase == 'train':
                scheduler.step()

            epoch_loss = running_loss / len(dataloaders[phase].dataset)
            epoch_acc = running_corrects.double() / len(dataloaders[phase].dataset)

            logger.info(f'{phase} Loss: {epoch_loss:.4f} Acc: {epoch_acc:.4f}')

            if phase == 'val' and epoch_acc > best_acc:
                best_acc = epoch_acc
                best_model_wts = model.state_dict()

    model.load_state_dict(best_model_wts)
    return model

# Function to evaluate model
def evaluate_model(model, dataloader, criterion, device):
    model.eval()
    running_loss = 0.0
    running_corrects = 0
    all_preds = []
    all_labels = []

    with torch.no_grad():
        for batch in dataloader:
            inputs = batch['input_ids'].to(device)
            masks = batch['attention_mask'].to(device)
            labels = batch['label'].to(device)

            outputs = model(inputs, masks)
            _, preds = torch.max(outputs, 1)
            loss = criterion(outputs, labels)

            running_loss += loss.item() * inputs.size(0)
            running_corrects += torch.sum(preds == labels.data)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

    loss = running_loss / len(dataloader.dataset)
    acc = running_corrects.double() / len(dataloader.dataset)
    f1 = f1_score(all_labels, all_preds, average='weighted')

    logger.info(f'Test Loss: {loss:.4f} Acc: {acc:.4f} F1: {f1:.4f}')

    return loss, acc, f1

# Main function to fine-tune model
def main():
    # Load data
    train_df = pd.read_csv(config['data']['training_data_path'])
    val_df = pd.read_csv(config['data']['validation_data_path'])
    test_df = pd.read_csv(config['data']['test_data_path'])

    # Tokenizer setup
    tokenizer = lambda x: x.split()  # Placeholder tokenizer function

    # Dataset and DataLoader setup
    train_dataset = ConversationDataset(train_df['text'].tolist(), train_df['label'].tolist(), tokenizer, config['model']['max_len'])
    val_dataset = ConversationDataset(val_df['text'].tolist(), val_df['label'].tolist(), tokenizer, config['model']['max_len'])
    test_dataset = ConversationDataset(test_df['text'].tolist(), test_df['label'].tolist(), tokenizer, config['model']['max_len'])

    train_loader = DataLoader(train_dataset, batch_size=config['training_params']['batch_size'], shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=config['training_params']['batch_size'], shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=config['training_params']['batch_size'], shuffle=False)

    dataloaders = {'train': train_loader, 'val': val_loader}

    # Model setup
    model = ConversationModel(
        vocab_size=config['model']['vocab_size'],
        embed_size=config['model']['embed_size'],
        num_heads=config['model']['num_heads'],
        hidden_dim=config['model']['hidden_dim'],
        num_layers=config['model']['num_layers'],
        num_classes=config['model']['num_classes'],
        dropout=config['model']['dropout']
    )

    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    model = model.to(device)

    # Training setup
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=config['training_params']['learning_rate'])
    scheduler = optim.lr_scheduler.StepLR(optimizer, step_size=7, gamma=0.1)

    # Train model
    logger.info("Starting training")
    model = train_model(model, dataloaders, criterion, optimizer, scheduler, config['training_params']['num_epochs'], device)

    # Evaluate model
    logger.info("Evaluating model")
    test_loss, test_acc, test_f1 = evaluate_model(model, test_loader, criterion, device)

    # Save model
    torch.save(model.state_dict(), config['evaluation']['save_best_model_path'])
    logger.info(f"Model saved to {config['evaluation']['save_best_model_path']}")

if __name__ == '__main__':
    main()
