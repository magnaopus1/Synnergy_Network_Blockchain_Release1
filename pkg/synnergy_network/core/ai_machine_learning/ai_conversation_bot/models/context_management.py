import os
import yaml
import redis
import pickle
import logging
from collections import deque

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration
config_path = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/context_management_config.yaml'
with open(config_path, 'r') as file:
    config = yaml.safe_load(file)

class ContextManagement:
    def __init__(self):
        self.redis_host = config['redis']['host']
        self.redis_port = config['redis']['port']
        self.redis_password = config['redis']['password']
        self.context_window_size = config['context']['window_size']
        self.context_expiration = config['context']['expiration']
        self.cache = redis.Redis(
            host=self.redis_host,
            port=self.redis_port,
            password=self.redis_password
        )

    def save_context(self, user_id, context_data):
        try:
            context_queue = self.get_context(user_id)
            context_queue.append(context_data)
            if len(context_queue) > self.context_window_size:
                context_queue.popleft()

            self.cache.setex(user_id, self.context_expiration, pickle.dumps(context_queue))
            logger.info(f"Context for user {user_id} updated successfully.")
        except Exception as e:
            logger.error(f"Error saving context for user {user_id}: {e}")

    def get_context(self, user_id):
        try:
            context_data = self.cache.get(user_id)
            if context_data:
                context_queue = pickle.loads(context_data)
                logger.info(f"Context for user {user_id} retrieved successfully.")
                return context_queue
            else:
                logger.info(f"No context found for user {user_id}.")
                return deque(maxlen=self.context_window_size)
        except Exception as e:
            logger.error(f"Error retrieving context for user {user_id}: {e}")
            return deque(maxlen=self.context_window_size)

    def clear_context(self, user_id):
        try:
            self.cache.delete(user_id)
            logger.info(f"Context for user {user_id} cleared successfully.")
        except Exception as e:
            logger.error(f"Error clearing context for user {user_id}: {e}")

    def update_context(self, user_id, new_data):
        try:
            context_queue = self.get_context(user_id)
            context_queue.append(new_data)
            if len(context_queue) > self.context_window_size:
                context_queue.popleft()
            self.save_context(user_id, list(context_queue))
            logger.info(f"Context for user {user_id} updated successfully with new data.")
        except Exception as e:
            logger.error(f"Error updating context for user {user_id}: {e}")

    def get_full_context(self, user_id):
        context = self.get_context(user_id)
        return list(context)

if __name__ == "__main__":
    context_manager = ContextManagement()

    # Example usage
    user_id = "user123"
    context_data = {"message": "Hello, how can I help you today?", "intent": "greeting"}

    # Save context
    context_manager.save_context(user_id, context_data)

    # Retrieve context
    retrieved_context = context_manager.get_context(user_id)
    print(f"Retrieved context for {user_id}: {retrieved_context}")

    # Update context
    new_data = {"message": "Can you tell me about blockchain?", "intent": "inquiry"}
    context_manager.update_context(user_id, new_data)

    # Get full context
    full_context = context_manager.get_full_context(user_id)
    print(f"Full context for {user_id}: {full_context}")

    # Clear context
    context_manager.clear_context(user_id)
