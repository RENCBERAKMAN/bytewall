"""Ollama (yerel LLM) ile iletisim katmani."""
from core.config import settings


class OllamaClient:
    def __init__(self):
        self.host = settings.ollama_host
        self.model = settings.ollama_model

    def generate(self, prompt: str) -> str:
        # TODO: requests ile Ollama /api/generate endpoint'ine POST
        raise NotImplementedError
