import os
import shutil
import logging
import yaml
from pathlib import Path
from datetime import datetime
from model_evaluation import evaluate_model
from save_trained_model import save_model_to_storage

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
deployment_config = load_config('deployment_config.yaml')
model_storage_config = load_config('model_storage_config.yaml')

def deploy_model(new_model_path, deployment_notes):
    """Function to handle the deployment of the AI conversation bot model."""
    logger.info("Starting deployment process...")
    
    deployment_dir = Path(deployment_config['deployment_directory'])
    if not deployment_dir.exists():
        logger.error(f"Deployment directory {deployment_dir} does not exist.")
        return
    
    # Save the new model to the model storage
    new_model_storage_path = save_model_to_storage(new_model_path, model_storage_config)
    if not new_model_storage_path:
        logger.error("Failed to save the new model. Aborting deployment.")
        return
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    new_model_deployment_path = deployment_dir / f"model_{timestamp}.pth"
    shutil.copy2(new_model_storage_path, new_model_deployment_path)
    
    # Backup the current model
    current_model_symlink = deployment_dir / 'current_model.pth'
    if current_model_symlink.exists() or current_model_symlink.is_symlink():
        current_model_backup_path = deployment_dir / f"backup_{timestamp}.pth"
        current_model_path = current_model_symlink.resolve()
        shutil.copy2(current_model_path, current_model_backup_path)
        current_model_symlink.unlink()
    
    # Update the symlink to point to the new model
    current_model_symlink.symlink_to(new_model_deployment_path)
    logger.info(f"Model deployed successfully to {new_model_deployment_path}")
    
    # Validate the new model
    if not validate_new_model(new_model_deployment_path):
        logger.error("New model validation failed. Rolling back to previous model.")
        rollback_model(current_model_backup_path, current_model_symlink)
        return
    
    # Save deployment notes
    save_deployment_notes(deployment_notes, timestamp, new_model_deployment_path)
    
    logger.info("Deployment process completed successfully.")

def validate_new_model(model_path):
    """Function to validate the new model."""
    logger.info(f"Validating the new model at {model_path}")
    # This function should implement actual model validation logic
    return evaluate_model(model_path)

def rollback_model(backup_model_path, current_model_symlink):
    """Rollback to the previous model in case of failure."""
    logger.info(f"Rolling back to the previous model at {backup_model_path}")
    if backup_model_path.exists():
        current_model_symlink.unlink()
        current_model_symlink.symlink_to(backup_model_path)
        logger.info("Rollback completed successfully.")
    else:
        logger.error(f"Backup model {backup_model_path} does not exist. Rollback failed.")

def save_deployment_notes(deployment_notes, timestamp, model_path):
    """Save deployment notes to a log file."""
    notes_dir = Path(deployment_config['deployment_notes_directory'])
    notes_dir.mkdir(parents=True, exist_ok=True)
    notes_file = notes_dir / f"deployment_notes_{timestamp}.log"
    
    with open(notes_file, 'w') as file:
        file.write(f"Deployment Timestamp: {timestamp}\n")
        file.write(f"Model Path: {model_path}\n")
        file.write(f"Deployment Notes: {deployment_notes}\n")
    
    logger.info(f"Deployment notes saved to {notes_file}")

if __name__ == '__main__':
    new_model_path = input("Enter the path to the new model: ")
    deployment_notes = input("Enter deployment notes: ")
    deploy_model(new_model_path, deployment_notes)
