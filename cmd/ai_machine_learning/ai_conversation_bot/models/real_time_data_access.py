import os
import json
import yaml
import requests
import logging
import redis
import time
from threading import Thread, Event

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration
config_path = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/real_time_data_access_config.yaml'
with open(config_path, 'r') as file:
    config = yaml.safe_load(file)

class RealTimeDataAccess:
    def __init__(self):
        self.api_endpoints = config['api_endpoints']
        self.cache = redis.Redis(
            host=config['redis']['host'],
            port=config['redis']['port'],
            password=config['redis']['password']
        )
        self.update_interval = config['update_interval']
        self.stop_event = Event()

    def fetch_data(self, url):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Error fetching data from {url}: {e}")
            return None

    def update_cache(self):
        while not self.stop_event.is_set():
            for key, url in self.api_endpoints.items():
                data = self.fetch_data(url)
                if data:
                    self.cache.set(key, json.dumps(data))
                    logger.info(f"Updated cache for {key}")
            time.sleep(self.update_interval)

    def get_data(self, key):
        data = self.cache.get(key)
        if data:
            return json.loads(data)
        return None

    def start(self):
        self.update_thread = Thread(target=self.update_cache)
        self.update_thread.start()

    def stop(self):
        self.stop_event.set()
        self.update_thread.join()

if __name__ == '__main__':
    data_access = RealTimeDataAccess()
    try:
        data_access.start()
        # Example usage
        while True:
            time.sleep(5)
            for key in config['api_endpoints']:
                data = data_access.get_data(key)
                if data:
                    logger.info(f"Data for {key}: {data}")
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        data_access.stop()
