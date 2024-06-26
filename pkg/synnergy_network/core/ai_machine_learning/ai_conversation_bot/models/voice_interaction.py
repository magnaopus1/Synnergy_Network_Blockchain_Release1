import torch
import torch.nn as nn
import torchaudio
from torchaudio.transforms import MelSpectrogram, AmplitudeToDB
import logging

class VoiceInteractionModel(nn.Module):
    def __init__(self, num_classes=10, num_mel_bins=64, hidden_dim=256, num_layers=4, dropout_rate=0.3):
        super(VoiceInteractionModel, self).__init__()
        self.mel_spectrogram = MelSpectrogram(
            sample_rate=16000,
            n_fft=400,
            win_length=400,
            hop_length=160,
            n_mels=num_mel_bins
        )
        self.amplitude_to_db = AmplitudeToDB()
        self.rnn = nn.LSTM(
            input_size=num_mel_bins,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            dropout=dropout_rate,
            batch_first=True
        )
        self.fc = nn.Linear(hidden_dim, num_classes)
        self.log_softmax = nn.LogSoftmax(dim=1)

    def forward(self, x):
        x = self.mel_spectrogram(x)
        x = self.amplitude_to_db(x)
        x = x.permute(0, 2, 1)  # [batch, time, mel]
        x, _ = self.rnn(x)
        x = self.fc(x[:, -1, :])
        x = self.log_softmax(x)
        return x

def train(model, train_loader, criterion, optimizer, device):
    model.train()
    total_loss = 0
    correct = 0
    total = 0
    for batch in train_loader:
        inputs, labels = batch
        inputs, labels = inputs.to(device), labels.to(device)

        optimizer.zero_grad()
        outputs = model(inputs)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()

        total_loss += loss.item()
        _, predicted = torch.max(outputs.data, 1)
        total += labels.size(0)
        correct += (predicted == labels).sum().item()

    avg_loss = total_loss / len(train_loader)
    accuracy = 100 * correct / total
    return avg_loss, accuracy

def evaluate(model, val_loader, criterion, device):
    model.eval()
    total_loss = 0
    correct = 0
    total = 0
    with torch.no_grad():
        for batch in val_loader:
            inputs, labels = batch
            inputs, labels = inputs.to(device), labels.to(device)

            outputs = model(inputs)
            loss = criterion(outputs, labels)

            total_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()

    avg_loss = total_loss / len(val_loader)
    accuracy = 100 * correct / total
    return avg_loss, accuracy

def main():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    # Load configurations
    config_path = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/training_config.yaml'
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)

    # Set device
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Load data
    train_data = MyDataset(config['training']['data']['train_data_path'])
    val_data = MyDataset(config['training']['data']['validation_data_path'])
    test_data = MyDataset(config['training']['data']['test_data_path'])

    train_loader = DataLoader(train_data, batch_size=config['training']['data']['batch_size'], shuffle=True, num_workers=config['training']['data']['num_workers'])
    val_loader = DataLoader(val_data, batch_size=config['training']['data']['batch_size'], shuffle=False, num_workers=config['training']['data']['num_workers'])
    test_loader = DataLoader(test_data, batch_size=config['training']['data']['batch_size'], shuffle=False, num_workers=config['training']['data']['num_workers'])

    # Initialize model
    model = VoiceInteractionModel(
        num_classes=config['model']['num_classes'],
        num_mel_bins=config['model']['num_mel_bins'],
        hidden_dim=config['model']['hidden_dim'],
        num_layers=config['model']['num_layers'],
        dropout_rate=config['model']['dropout_rate']
    ).to(device)

    # Define loss and optimizer
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=config['training_params']['learning_rate'])

    # Training loop
    best_val_loss = float('inf')
    patience_counter = 0

    for epoch in range(config['training_params']['num_epochs']):
        train_loss, train_accuracy = train(model, train_loader, criterion, optimizer, device)
        val_loss, val_accuracy = evaluate(model, val_loader, criterion, device)
        logger.info(f"Epoch [{epoch + 1}/{config['training_params']['num_epochs']}], "
                    f"Train Loss: {train_loss:.4f}, Train Accuracy: {train_accuracy:.2f}%, "
                    f"Validation Loss: {val_loss:.4f}, Validation Accuracy: {val_accuracy:.2f}%")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), config['evaluation']['save_best_model_path'])
            patience_counter = 0
        else:
            patience_counter += 1

        if config['training_params']['early_stopping']['enable'] and patience_counter >= config['training_params']['early_stopping']['patience']:
            logger.info("Early stopping triggered")
            break

    # Test the model
    test_loss, test_accuracy = evaluate(model, test_loader, criterion, device)
    logger.info(f"Test Loss: {test_loss:.4f}, Test Accuracy: {test_accuracy:.2f}%")

    # Save the final model
    torch.save(model.state_dict(), os.path.join(config['evaluation']['save_best_model_path'], 'final_model.pt'))

if __name__ == '__main__':
    main()
