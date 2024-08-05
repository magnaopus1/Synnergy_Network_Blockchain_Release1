import os
import yaml
import logging
import time
from datetime import datetime
from pathlib import Path
from shutil import copy2
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
training_config = load_config('training_config.yaml')
model_storage_config = load_config('model_storage_config.yaml')
logging_monitoring_config = load_config('logging_monitoring_config.yaml')

def deploy_model():
    """Main function to deploy the AI model."""
    logger.info("Starting model deployment process...")
    
    # Evaluate the model
    evaluation_result = evaluate_model(training_config)
    if not evaluation_result['success']:
        logger.error("Model evaluation failed. Aborting deployment.")
        return
    
    # Save the model
    model_path = save_model_to_storage(evaluation_result['model'], model_storage_config)
    if not model_path:
        logger.error("Failed to save the model. Aborting deployment.")
        return
    
    # Copy model to deployment directory
    deployment_dir = Path(deployment_config['deployment_directory'])
    if not deployment_dir.exists():
        logger.info(f"Creating deployment directory at {deployment_dir}")
        deployment_dir.mkdir(parents=True)
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    model_deployment_path = deployment_dir / f"model_{timestamp}.pth"
    copy2(model_path, model_deployment_path)
    
    # Update the current model symlink
    current_model_symlink = deployment_dir / 'current_model.pth'
    if current_model_symlink.exists() or current_model_symlink.is_symlink():
        current_model_symlink.unlink()
    current_model_symlink.symlink_to(model_deployment_path)
    
    logger.info(f"Model deployed successfully at {model_deployment_path}")
    
    # Perform additional steps if necessary
    if deployment_config.get('post_deployment_steps'):
        for step in deployment_config['post_deployment_steps']:
            execute_post_deployment_step(step)
    
    logger.info("Model deployment process completed.")

def execute_post_deployment_step(step):
    """Execute additional steps after model deployment."""
    logger.info(f"Executing post-deployment step: {step}")
    # Implement specific steps as needed, for example:
    if step == 'send_notification':
        send_notification()
    elif step == 'update_monitoring':
        update_monitoring()

def send_notification():
    """Send a notification about the deployment."""
    # Implement notification logic (e.g., email, Slack, etc.)
    logger.info("Sending deployment notification...")

def update_monitoring():
    """Update monitoring settings for the new deployment."""
    # Implement monitoring update logic
    logger.info("Updating monitoring settings...")

if __name__ == '__main__':
    deploy_model()
