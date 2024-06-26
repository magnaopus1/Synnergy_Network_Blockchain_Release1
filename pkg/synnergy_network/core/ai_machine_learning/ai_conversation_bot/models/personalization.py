import os
import json
import yaml
import logging
from datetime import datetime
from collections import defaultdict
import redis
import hashlib
import pickle

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration
config_path = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/personalization_config.yaml'
with open(config_path, 'r') as file:
    config = yaml.safe_load(file)

class Personalization:
    def __init__(self):
        self.redis_host = config['redis']['host']
        self.redis_port = config['redis']['port']
        self.redis_password = config['redis']['password']
        self.cache = redis.Redis(
            host=self.redis_host,
            port=self.redis_port,
            password=self.redis_password
        )
        self.user_profiles = defaultdict(dict)
        self.load_profiles()

    def load_profiles(self):
        try:
            profiles = self.cache.get('user_profiles')
            if profiles:
                self.user_profiles = pickle.loads(profiles)
                logger.info("User profiles loaded from cache.")
            else:
                logger.info("No user profiles found in cache.")
        except Exception as e:
            logger.error(f"Error loading user profiles: {e}")

    def save_profiles(self):
        try:
            self.cache.set('user_profiles', pickle.dumps(self.user_profiles))
            logger.info("User profiles saved to cache.")
        except Exception as e:
            logger.error(f"Error saving user profiles: {e}")

    def hash_user_id(self, user_id):
        return hashlib.sha256(user_id.encode()).hexdigest()

    def update_user_profile(self, user_id, interaction_data):
        hashed_user_id = self.hash_user_id(user_id)
        user_profile = self.user_profiles[hashed_user_id]

        for key, value in interaction_data.items():
            if key in user_profile:
                user_profile[key].append(value)
            else:
                user_profile[key] = [value]

        self.user_profiles[hashed_user_id] = user_profile
        self.save_profiles()

    def get_user_profile(self, user_id):
        hashed_user_id = self.hash_user_id(user_id)
        return self.user_profiles.get(hashed_user_id, {})

    def generate_personalized_response(self, user_id, message):
        user_profile = self.get_user_profile(user_id)

        # Placeholder for a more complex personalization logic
        if 'preferences' in user_profile:
            preferences = user_profile['preferences']
            response = f"Based on your preferences ({preferences}), I suggest: ..."
        else:
            response = "Here's a general suggestion for you."

        return response

    def log_interaction(self, user_id, message, response):
        interaction_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'message': message,
            'response': response
        }
        self.update_user_profile(user_id, interaction_data)

    def personalize_and_respond(self, user_id, message):
        response = self.generate_personalized_response(user_id, message)
        self.log_interaction(user_id, message, response)
        return response

if __name__ == '__main__':
    personalization = Personalization()

    # Example usage
    user_id = "user123"
    message = "What can you recommend for blockchain investments?"

    response = personalization.personalize_and_respond(user_id, message)
    logger.info(f"Response to {user_id}: {response}")
