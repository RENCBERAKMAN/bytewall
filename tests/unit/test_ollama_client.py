"""
tests/unit/test_ollama_client.py

requests.post çağrılarını mock'luyoruz — gerçek Ollama kurulu
olmasa/çalışmasa bile testler hızlı ve güvenilir çalışır.
"""

import requests
from unittest.mock import patch, MagicMock

import pytest

from ai.ollama_client import OllamaClient, OllamaConnectionError, OllamaResponseError


@pytest.fixture
def client() -> OllamaClient:
    return OllamaClient(host="http://127.0.0.1:11434", model="llama3", timeout=10)


def test_successful_generate_returns_response_text(client: OllamaClient):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {
        "model": "llama3",
        "response": "merhaba, ben bir cevabım",
        "done": True,
    }
    with patch("requests.post", return_value=mock_response) as mock_post:
        result = client.generate("test prompt")

        assert result == "merhaba, ben bir cevabım"
        mock_post.assert_called_once()
        # stream=False gönderildiğini doğrula — tüm cevabı tek seferde almak istiyoruz
        _, kwargs = mock_post.call_args
        assert kwargs["json"]["stream"] is False
        assert kwargs["json"]["model"] == "llama3"


def test_connection_error_raises_custom_exception(client: OllamaClient):
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError()):
        with pytest.raises(OllamaConnectionError):
            client.generate("test prompt")


def test_timeout_raises_custom_exception(client: OllamaClient):
    with patch("requests.post", side_effect=requests.exceptions.Timeout()):
        with pytest.raises(OllamaConnectionError):
            client.generate("test prompt")


def test_non_200_status_raises_response_error(client: OllamaClient):
    mock_response = MagicMock(status_code=500, text="internal error")
    with patch("requests.post", return_value=mock_response):
        with pytest.raises(OllamaResponseError):
            client.generate("test prompt")


def test_invalid_json_raises_response_error(client: OllamaClient):
    mock_response = MagicMock(status_code=200)
    mock_response.json.side_effect = ValueError("not json")
    with patch("requests.post", return_value=mock_response):
        with pytest.raises(OllamaResponseError):
            client.generate("test prompt")


def test_missing_response_field_raises_response_error(client: OllamaClient):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {"model": "llama3", "done": True}  # 'response' eksik
    with patch("requests.post", return_value=mock_response):
        with pytest.raises(OllamaResponseError):
            client.generate("test prompt")