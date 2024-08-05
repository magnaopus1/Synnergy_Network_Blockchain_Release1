import os
import yaml
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix, classification_report
import pandas as pd
import numpy as np
import logging
import seaborn as sns
import matplotlib.pyplot as plt

# Load configuration
config_path = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/evaluation_config.yaml'
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
    precision = precision_score(all_labels, all_preds, average='weighted')
    recall = recall_score(all_labels, all_preds, average='weighted')

    logger.info(f'Test Loss: {loss:.4f} Acc: {acc:.4f} F1: {f1:.4f} Precision: {precision:.4f} Recall: {recall:.4f}')

    # Confusion Matrix
    conf_matrix = confusion_matrix(all_labels, all_preds)
    plt.figure(figsize=(10, 7))
    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.savefig(config['evaluation']['confusion_matrix_path'])
    logger.info(f"Confusion matrix saved to {config['evaluation']['confusion_matrix_path']}")

    # Classification Report
    class_report = classification_report(all_labels, all_preds, target_names=config['data']['label_names'])
    logger.info(f'Classification Report:\n{class_report}')

    with open(config['evaluation']['classification_report_path'], 'w') as f:
        f.write(class_report)
    logger.info(f"Classification report saved to {config['evaluation']['classification_report_path']}")

    return loss, acc, f1, precision, recall

# Main function for model evaluation
def main():
    # Load data
    test_df = pd.read_csv(config['data']['test_data_path'])

    # Tokenizer setup
    tokenizer = lambda x: x.split()  # Placeholder tokenizer function

    # Dataset and DataLoader setup
    test_dataset = ConversationDataset(test_df['text'].tolist(), test_df['label'].tolist(), tokenizer, config['model']['max_len'])
    test_loader = DataLoader(test_dataset, batch_size=config['evaluation']['batch_size'], shuffle=False)

    # Model setup
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    model = ConversationModel(
        vocab_size=config['model']['vocab_size'],
        embed_size=config['model']['embed_size'],
        num_heads=config['model']['num_heads'],
        hidden_dim=config['model']['hidden_dim'],
        num_layers=config['model']['num_layers'],
        num_classes=config['model']['num_classes'],
        dropout=config['model']['dropout']
    ).to(device)

    model.load_state_dict(torch.load(config['evaluation']['model_path'], map_location=device))
    criterion = nn.CrossEntropyLoss()

    logger.info("Starting model evaluation")
    evaluate_model(model, test_loader, criterion, device)
    logger.info("Model evaluation completed")

if __name__ == '__main__':
    main()
