import os
import logging
import pickle
import yaml
from datetime import datetime
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load configuration files
CONFIG_DIR = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/'

def load_config(file_name):
    try:
        with open(os.path.join(CONFIG_DIR, file_name), 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        logger.error(f"Error loading config {file_name}: {e}")
        return None

# Load specific configurations
model_storage_config = load_config('model_storage_config.yaml')
training_config = load_config('training_config.yaml')

def save_model(model, model_name):
    """Function to save the trained model."""
    logger.info("Starting model save process...")

    model_dir = Path(model_storage_config['model_directory'])
    model_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    model_file_path = model_dir / f"{model_name}_{timestamp}.pkl"

    try:
        with open(model_file_path, 'wb') as file:
            pickle.dump(model, file)
        logger.info(f"Model saved successfully at {model_file_path}")
    except Exception as e:
        logger.error(f"Failed to save model: {e}")

def save_metadata(model_name, training_params, metrics):
    """Function to save model metadata."""
    metadata_dir = Path(model_storage_config['metadata_directory'])
    metadata_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    metadata_file_path = metadata_dir / f"{model_name}_metadata_{timestamp}.yaml"

    metadata = {
        'model_name': model_name,
        'timestamp': timestamp,
        'training_params': training_params,
        'metrics': metrics
    }

    try:
        with open(metadata_file_path, 'w') as file:
            yaml.dump(metadata, file)
        logger.info(f"Metadata saved successfully at {metadata_file_path}")
    except Exception as e:
        logger.error(f"Failed to save metadata: {e}")

def main():
    """Main function to save the trained model and its metadata."""
    # Placeholder for the actual model object
    model = "trained_model_object"

    # Example model name
    model_name = training_config['model_name']

    # Placeholder for training parameters and metrics
    training_params = {
        'learning_rate': training_config['learning_rate'],
        'batch_size': training_config['batch_size'],
        'epochs': training_config['epochs'],
        'optimizer': training_config['optimizer']
    }
    metrics = {
        'accuracy': 0.95,
        'loss': 0.05,
        'val_accuracy': 0.94,
        'val_loss': 0.06
    }

    save_model(model, model_name)
    save_metadata(model_name, training_params, metrics)

if __name__ == '__main__':
    main()
