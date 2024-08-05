import os
import yaml
import logging
from .context_management import ContextManagement
from .general_language_understanding import GeneralLanguageUnderstanding
from .intent_recognition import IntentRecognition
from .multi_language_support import MultiLanguageSupport
from .personalization import Personalization
from .real_time_data_access import RealTimeDataAccess
from .response_generation import ResponseGeneration
from .security_models import SecurityModels
from .sentiment_analysis import SentimentAnalysis
from .voice_interaction import VoiceInteraction

# Setup logging
logging.basicConfig(level=logging.INFO)
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

# Load individual configurations
bot_parameters = load_config('bot_parameters.yaml')
context_management_config = load_config('context_management_config.yaml')
conversation_bot_config = load_config('conversation_bot_config.yaml')
deployment_config = load_config('deployment_config.yaml')
logging_monitoring_config = load_config('logging_monitoring_config.yaml')
model_storage_config = load_config('model_storage_config.yaml')
personalization_config = load_config('personalization_config.yaml')
security_config = load_config('security_config.yaml')
training_config = load_config('training_config.yaml')

# Initialize models
context_manager = ContextManagement(context_management_config)
general_language_understanding = GeneralLanguageUnderstanding(conversation_bot_config)
intent_recognition = IntentRecognition(conversation_bot_config)
multi_language_support = MultiLanguageSupport(conversation_bot_config)
personalization = Personalization(personalization_config)
real_time_data_access = RealTimeDataAccess(conversation_bot_config)
response_generation = ResponseGeneration(conversation_bot_config)
security_models = SecurityModels(security_config)
sentiment_analysis = SentimentAnalysis(conversation_bot_config)
voice_interaction = VoiceInteraction(conversation_bot_config)

__all__ = [
    'context_manager',
    'general_language_understanding',
    'intent_recognition',
    'multi_language_support',
    'personalization',
    'real_time_data_access',
    'response_generation',
    'security_models',
    'sentiment_analysis',
    'voice_interaction'
]
