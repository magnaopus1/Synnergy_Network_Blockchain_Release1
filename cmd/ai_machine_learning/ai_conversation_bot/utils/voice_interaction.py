import yaml
import logging
import speech_recognition as sr
import pyttsx3

class VoiceInteraction:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self.load_config()
        self.setup_logging()
        self.recognizer = sr.Recognizer()
        self.microphone = sr.Microphone()
        self.tts_engine = pyttsx3.init()
        self.setup_tts()

    def load_config(self) -> dict:
        with open(self.config_path, 'r') as file:
            config = yaml.safe_load(file)
        return config

    def setup_logging(self):
        logging_config = self.config.get('logging', {})
        logging.basicConfig(
            filename=logging_config.get('log_file', 'voice_interaction.log'),
            level=logging_config.get('log_level', logging.INFO),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('VoiceInteraction')

    def setup_tts(self):
        tts_config = self.config.get('tts', {})
        self.tts_engine.setProperty('rate', tts_config.get('rate', 150))
        self.tts_engine.setProperty('volume', tts_config.get('volume', 1.0))
        voices = self.tts_engine.getProperty('voices')
        voice_id = tts_config.get('voice_id', None)
        if voice_id:
            self.tts_engine.setProperty('voice', voices[voice_id].id)
        else:
            self.tts_engine.setProperty('voice', voices[0].id)

    def recognize_speech(self) -> str:
        self.logger.info("Listening for speech input...")
        with self.microphone as source:
            audio = self.recognizer.listen(source)
        try:
            text = self.recognizer.recognize_google(audio)
            self.logger.info(f"Recognized speech: {text}")
            return text
        except sr.UnknownValueError:
            self.logger.error("Google Speech Recognition could not understand audio")
            return "Sorry, I did not understand that."
        except sr.RequestError as e:
            self.logger.error(f"Could not request results from Google Speech Recognition service; {e}")
            return "Sorry, there was an error with the speech recognition service."

    def respond(self, text: str):
        self.logger.info(f"Responding with: {text}")
        self.tts_engine.say(text)
        self.tts_engine.runAndWait()

    def handle_conversation(self):
        while True:
            user_input = self.recognize_speech()
            if user_input.lower() == 'exit':
                self.respond("Goodbye!")
                break
            response = self.generate_response(user_input)
            self.respond(response)

    def generate_response(self, text: str) -> str:
        # Placeholder for actual response generation logic
        self.logger.info(f"Generating response for: {text}")
        response = f"You said: {text}"
        return response

if __name__ == "__main__":
    config_file_path = "/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/voice_interaction_config.yaml"
    voice_interaction = VoiceInteraction(config_file_path)
    voice_interaction.handle_conversation()
