"""
ai/ollama_client.py

Ollama'nın yerel HTTP API'siyle (varsayılan: http://localhost:11434)
iletişim kuran ince bir katman. Ollama kurulunca arka planda bu
API'yi otomatik olarak dinlemeye başlar — biz sadece ona HTTP
isteği atıyoruz, ekstra bir "sunucu başlatma" işimiz yok.

API formatı (gerçek Ollama /api/generate cevabı):
{
  "model": "llama3",
  "created_at": "...",
  "response": "<modelin ürettiği metin>",
  "done": true
}
"""

from __future__ import annotations

import requests

from core.config import settings
from core.logger import get_logger

logger = get_logger("bytewall.ollama_client")


class OllamaConnectionError(Exception):
    """Ollama'ya bağlanılamadı — muhtemelen Ollama çalışmıyor."""


class OllamaResponseError(Exception):
    """Ollama cevap verdi ama beklenmeyen bir formatta/hata koduyla."""


class OllamaClient:
    def __init__(self, host: str | None = None, model: str | None = None, timeout: int = 120):
        # None verilirse core/config.py'daki varsayılanları kullan —
        # böylece hem test'te özelleştirilebilir hem de normal
        # kullanımda .env'den otomatik okunur.
        self.host = (host or settings.ollama_host).rstrip("/")
        self.model = model or settings.ollama_model
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        """
        Prompt'u Ollama'ya gönderir, modelin ürettiği ham metni döner.
        JSON çözümleme/parse işini BURADA yapmıyoruz — bu, çağıran
        kodun (analyzer.py) sorumluluğu. Bu katman sadece "prompt gönder,
        cevap al" işiyle ilgilenir (tek sorumluluk ilkesi).
        """
        url = f"{self.host}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,  # tüm cevabı tek seferde al, parça parça değil
        }

        try:
            response = requests.post(url, json=payload, timeout=self.timeout)
        except requests.exceptions.ConnectionError as e:
            raise OllamaConnectionError(
                f"Ollama'ya bağlanılamadı ({self.host}). Ollama çalışıyor mu? "
                f"'ollama serve' ya da Ollama uygulamasının açık olduğundan emin ol."
            ) from e
        except requests.exceptions.Timeout as e:
            raise OllamaConnectionError(
                f"Ollama {self.timeout} saniye içinde cevap vermedi."
            ) from e

        if response.status_code != 200:
            raise OllamaResponseError(
                f"Ollama hata kodu döndürdü ({response.status_code}): {response.text[:300]}"
            )

        try:
            data = response.json()
        except ValueError as e:
            raise OllamaResponseError(f"Ollama cevabı geçerli JSON değil: {e}") from e

        if "response" not in data:
            raise OllamaResponseError(
                f"Ollama cevabında beklenen 'response' alanı yok: {data}"
            )

        return data["response"]