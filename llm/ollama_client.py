# llm/ollama_client.py
from ollama import Client
from core.config import config

class OllamaClient:
    """Wrapper around Ollama API for security testing tasks"""

    def __init__(self):
        self.client = Client(host=config.OLLAMA_HOST)
        self.fast_model = config.FAST_MODEL
        self.deep_model = config.DEEP_MODEL

    def chat(self, prompt, use_deep_model=False):
        """Send a prompt and get a response"""
        model = self.deep_model if use_deep_model else self.fast_model
        try:
            response = self.client.chat(
                model=model,
                messages=[{"role": "user", "content": prompt}]
            )
            return response['message']['content']
        except Exception as e:
            print(f"[LLM] Error communicating with Ollama: {e}")
            return None

    def test_connection(self):
        """Test if Ollama is running and models are available"""
        print("[LLM] Testing Ollama connection...")
        result = self.chat("Reply with: Ollama connection successful.")
        if result:
            print(f"[LLM] ✅ Connection OK — Model response: {result}")
            return True
        else:
            print("[LLM] ❌ Connection failed. Is Ollama running?")
            return False