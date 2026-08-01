"""
ai/analyzer.py

Finding listesini alır, her biri için Ollama'ya "bu gerçek bir risk mi,
özet nedir" diye sorar, cevabı Finding nesnesine (ai_summary,
false_positive alanları) işler.

TASARIM KARARI: AI, tool'un (Nmap/Nuclei) verdiği severity'yi
DEĞİŞTİRMEZ — sadece yorum/bağlam ekler ve olası false positive
işaretler. Neden? Çünkü severity, CVSS gibi objektif bir skorlama
sistemine dayanıyor; AI'nin bunu "düzeltmesi" güven kaybına yol
açabilir (halüsinasyon riski). AI'nin katkısı YORUMLAMA katmanında,
skorlamayı DEĞİŞTİRME katmanında değil.
"""

from __future__ import annotations

import json
import re

from ai.ollama_client import OllamaClient, OllamaConnectionError, OllamaResponseError
from parsers.schema import Finding, Severity
from core.logger import get_logger

logger = get_logger("bytewall.analyzer")


# Severity'leri önceliklendirme sırasında karşılaştırmak için sayısal ağırlık.
# CRITICAL en yüksek öncelik, INFO en düşük.
_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


PROMPT_TEMPLATE = """You are an experienced cybersecurity analyst. Review the following scan finding.

Finding:
- Tool: {source_tool}
- Title: {title}
- Description: {description}
- Reported severity: {severity}
- Target: {affected_url}
- Evidence: {evidence}

Your task:
1. Assess whether this finding represents a real security risk or is likely a false positive.
2. Write a clear, non-technical 2-3 sentence summary in English.

Respond with ONLY the following JSON format, no other text:
{{"summary": "...", "false_positive": true/false}}
"""


def _build_prompt(finding: Finding) -> str:
    return PROMPT_TEMPLATE.format(
        source_tool=finding.source_tool,
        title=finding.title,
        description=finding.description or "(açıklama yok)",
        severity=finding.severity.value,
        affected_url=finding.affected_url or "(belirtilmemiş)",
        evidence=finding.evidence or "(kanıt yok)",
    )


def _extract_json(raw_text: str) -> dict:
    """
    LLM'ler bazen JSON'ı ```json ... ``` bloğu içine sarar, bazen
    öncesine/sonrasına açıklama ekler. Bu fonksiyon, metnin içindeki
    İLK geçerli JSON nesnesini bulmaya çalışır — modelin "temiz"
    cevap vermediği durumlarda bile parse başarısız olmasın diye.
    """
    text = raw_text.strip()

    # Önce doğrudan dene (model talimatı doğru uyguladıysa en hızlı yol)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # ```json ... ``` veya ``` ... ``` bloğu varsa içini çıkar
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except json.JSONDecodeError:
            pass

    # Son çare: ilk '{' ile son '}' arasını al
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            pass

    raise ValueError(f"JSON çıkarılamadı: {raw_text[:200]}")


def analyze_findings(findings: list[Finding], client: OllamaClient | None = None) -> list[Finding]:
    """
    Her Finding için Ollama'ya sorar, ai_summary ve false_positive
    alanlarını doldurur. AYNI Finding nesnelerini yerinde günceller
    VE aynı listeyi döner (kolay kullanım için).

    Tek bir bulguda hata olması (Ollama çökmesi, JSON parse hatası)
    DİĞER bulguların analiz edilmesini engellemez — orchestrator.py'daki
    "bir aracın hatası diğerini etkilemesin" prensibiyle aynı mantık.
    """
    active_client = client or OllamaClient()

    for finding in findings:
        prompt = _build_prompt(finding)
        try:
            raw_response = active_client.generate(prompt)
            parsed = _extract_json(raw_response)

            finding.ai_summary = parsed.get("summary", "").strip() or None
            finding.false_positive = bool(parsed.get("false_positive", False))

        except (OllamaConnectionError, OllamaResponseError) as e:
            # Ollama'ya hiç ulaşılamadıysa: bulguyu analiz edilmemiş
            # bırak (ai_summary=None), ama bulguyu KAYBETME.
            logger.warning("AI analizi başarısız (%s): %s", finding.id, e)
            finding.ai_summary = None

        except ValueError as e:
            # Model cevap verdi ama JSON'ı çıkaramadık — ham cevabı
            # en azından bir yerde saklamak faydalı olabilir, ama
            # şemayı bozmamak için sadece logluyoruz.
            logger.warning("AI cevabı çözümlenemedi (%s): %s", finding.id, e)
            finding.ai_summary = None

    return findings


def sort_by_priority(findings: list[Finding]) -> list[Finding]:
    """
    Bulguları önem sırasına göre sıralar:
      1. Severity (CRITICAL -> INFO)
      2. Aynı severity içinde, false_positive işaretlenmemiş olanlar önce

    AI'nin false_positive işaretlemesi, bulguyu SİLMEZ — sadece
    listenin sonuna doğru iter. Karar her zaman kullanıcıya ait.
    """
    return sorted(
        findings,
        key=lambda f: (
            -_SEVERITY_WEIGHT.get(f.severity, 0),
            f.false_positive,  # False (0) önce, True (1) sonra
        ),
    )