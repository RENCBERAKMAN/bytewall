"""
Merkezi konfigurasyon. Tum ayarlar buradan okunur, hicbir yerde
hardcoded key/secret olmamali.
"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    log_level: str = "INFO"
    dry_run_default: bool = True

    class Config:
        env_file = ".env"


settings = Settings()
