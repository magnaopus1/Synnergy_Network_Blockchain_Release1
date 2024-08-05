import os
import json
import yaml
import logging
from langdetect import detect
from langdetect.lang_detect_exception import LangDetectException
from googletrans import Translator
from collections import defaultdict
import redis
import hashlib
import pickle

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration
config_path = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/multi_language_support_config.yaml'
with open(config_path, 'r') as file:
    config = yaml.safe_load(file)

class MultiLanguageSupport:
    def __init__(self):
        self.redis_host = config['redis']['host']
        self.redis_port = config['redis']['port']
        self.redis_password = config['redis']['password']
        self.cache = redis.Redis(
            host=self.redis_host,
            port=self.redis_port,
            password=self.redis_password
        )
        self.translator = Translator()
        self.user_languages = defaultdict(str)
        self.load_user_languages()

    def load_user_languages(self):
        try:
            languages = self.cache.get('user_languages')
            if languages:
                self.user_languages = pickle.loads(languages)
                logger.info("User languages loaded from cache.")
            else:
                logger.info("No user languages found in cache.")
        except Exception as e:
            logger.error(f"Error loading user languages: {e}")

    def save_user_languages(self):
        try:
            self.cache.set('user_languages', pickle.dumps(self.user_languages))
            logger.info("User languages saved to cache.")
        except Exception as e:
            logger.error(f"Error saving user languages: {e}")

    def hash_user_id(self, user_id):
        return hashlib.sha256(user_id.encode()).hexdigest()

    def detect_language(self, text):
        try:
            language = detect(text)
            return language
        except LangDetectException as e:
            logger.error(f"Language detection error: {e}")
            return None

    def update_user_language(self, user_id, language):
        hashed_user_id = self.hash_user_id(user_id)
        self.user_languages[hashed_user_id] = language
        self.save_user_languages()

    def get_user_language(self, user_id):
        hashed_user_id = self.hash_user_id(user_id)
        return self.user_languages.get(hashed_user_id, config['default_language'])

    def translate_text(self, text, src, dest):
        try:
            translated = self.translator.translate(text, src=src, dest=dest)
            return translated.text
        except Exception as e:
            logger.error(f"Translation error: {e}")
            return text

    def handle_message(self, user_id, message):
        language = self.detect_language(message)
        if language:
            self.update_user_language(user_id, language)
        else:
            language = self.get_user_language(user_id)

        if language != config['default_language']:
            translated_message = self.translate_text(message, src=language, dest=config['default_language'])
        else:
            translated_message = message

        return translated_message, language

    def generate_response(self, user_id, translated_message, original_language):
        # Placeholder for the actual response generation logic
        response = f"Response to '{translated_message}'"
        if original_language != config['default_language']:
            response = self.translate_text(response, src=config['default_language'], dest=original_language)
        return response

    def respond(self, user_id, message):
        translated_message, original_language = self.handle_message(user_id, message)
        response = self.generate_response(user_id, translated_message, original_language)
        return response

if __name__ == '__main__':
    multi_lang_support = MultiLanguageSupport()

    # Example usage
    user_id = "user123"
    message = "¿Cómo está el clima hoy?"

    response = multi_lang_support.respond(user_id, message)
    logger.info(f"Response to {user_id}: {response}")
