from google import genai
from google.genai import types
from google.genai.errors import APIError
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import json
import logging

from app.services.provider_guard import llm_cache, llm_semaphore, stable_key

# Setup clean, readable logger formatting
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishing_detector.llm_service")

# Define Pydantic models for Gemini structured output
class LlmPhishingSignal(BaseModel):
    id: str = Field(..., description="A snake_case identifier for this specific signal, e.g. urgency_pressure, sender_mismatch")
    severity: str = Field(..., description="The severity level: 'low', 'medium', or 'high'")
    title: str = Field(..., description="A short, catchy title summarizing the warning sign")
    description: str = Field(..., description="Explanation of why this was flagged and what it means to the user")

class LlmPhishingAnalysisSchema(BaseModel):
    risk_score: int = Field(..., description="Integer from 0 to 100 indicating the safety score (0 is completely safe, 100 is certain phishing)")
    status: str = Field(..., description="Classification: 'safe', 'warning', or 'danger'")
    phishing_signals: List[LlmPhishingSignal] = Field(default=[], description="List of social-engineering or technical anomalies detected")
    ai_explanation: str = Field(..., description="A comprehensive explanation formatted in Markdown detailing the threat analysis, suspicious elements, and safety advice.")

SYSTEM_INSTRUCTION = """
You are an advanced AI Cybersecurity Specialist specializing in Phishing and Social Engineering analysis.
Your job is to examine inputs (URLs, emails, or email headers) and perform a deep semantic analysis to determine if it is a phishing attempt.

Examine the content for:
1. Urgency/Threats: High-pressure tactics, fake deadlines, threats of suspension or financial penalties.
2. Baiting/Gifts: Offers of free products, refunds, tax rebates, inheritances, or unexpected bonuses.
3. Authority Spoofing: Impersonating trusted institutions like PayPal, banks, Microsoft, postal services, or company executives.
4. Data Requests: Asking for passwords, PINs, social security numbers, or credit card updates.
5. Inconsistencies: Mismatched links, suspicious domains, weird formatting, or poor grammar.

You will receive a list of rule-based heuristic signals already detected by the backend. Use them to augment your analysis. If the input is legitimate, explain why clearly and give it a low risk score.

Format the 'ai_explanation' field strictly in beautiful Markdown, including bullet points and headers. Do not output anything outside the requested JSON schema.
"""

def verify_gemini_key(api_key: str) -> Dict[str, Any]:
    """Validate a Gemini key without returning provider diagnostics or key material."""
    if not api_key or not api_key.strip():
        return {"valid": False, "error": "API key is not configured."}

    try:
        client = genai.Client(api_key=api_key.strip())
        if hasattr(client, "interactions"):
            client.interactions.create(
                model="models/gemini-3.6-flash",
                input="Verify connection test.",
            )
        else:
            client.models.generate_content(
                model="models/gemini-3.6-flash",
                contents="Verify connection test.",
            )
        logger.info("[SECURE] Gemini API key verification succeeded.")
        return {"valid": True}
    except Exception:
        logger.warning("[SECURE] Gemini API key verification failed.")
        return {"valid": False, "error": "Gemini API authentication failed."}

def get_fallback_analysis(input_type: str, content: str, heuristic_score: int, heuristic_signals: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Provides a graceful fallback report when Gemini API is unavailable or unconfigured."""
    logger.warning("Gemini API key not configured or failed. Generating fallback rule-based analysis.")
    
    # Calculate a rough score based on heuristic rules
    final_score = heuristic_score
    status = "safe"
    if final_score >= 70:
        status = "danger"
    elif final_score >= 30:
        status = "warning"
        
    ai_explanation = f"""### Heuristic Analysis Report (AI Analysis Offline)

*Note: The Gemini AI engine could not be contacted because the API Key is unconfigured or invalid. A heuristic fallback analysis was run instead.*

#### Findings Summary
- **Type Analyzed:** {input_type.upper()}
- **Threat Status:** **{status.upper()}** (Score: {final_score}/100)
- **Warning Signals Found:** {len(heuristic_signals)}

#### Heuristic Breakdown
"""
    if not heuristic_signals:
        ai_explanation += "\n- No specific security anomalies or suspicious patterns were detected in the input.\n"
    else:
        for idx, sig in enumerate(heuristic_signals, 1):
            ai_explanation += f"\n{idx}. **[{sig['severity'].upper()}] {sig['title']}**\n   {sig['description']}\n"
            
    ai_explanation += "\n#### Recommended Safety Steps\n"
    if status == "danger":
        ai_explanation += "- **Do not interact** with this content, click any links, or enter credentials.\n- Delete or report the email/URL immediately.\n"
    elif status == "warning":
        ai_explanation += "- Exercise extreme caution. Verify the sender/domain through independent channels (e.g. bookmarks or official app).\n"
    else:
        ai_explanation += "- The input seems relatively safe, but always verify sender credentials and secure lock symbols in your browser.\n"
        
    return {
        "risk_score": final_score,
        "status": status,
        "phishing_signals": heuristic_signals,
        "ai_explanation": ai_explanation
    }

async def analyze_with_llm(
    input_type: str, content: str, api_key: Optional[str], heuristic_score: int,
    heuristic_signals: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Analyze content with Gemini while bounding concurrency and repeat spend."""
    if not api_key:
        logger.info("Skipping LLM analysis: no server-side API key configured.")
        return get_fallback_analysis(input_type, content, heuristic_score, heuristic_signals)

    cache_key = stable_key("llm", f"{input_type}|{content}|{heuristic_score}|{json.dumps(heuristic_signals, sort_keys=True)}")
    cached = await llm_cache.get(cache_key)
    if cached is not None:
        return cached

    async with llm_semaphore:
        cached = await llm_cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            client = genai.Client(api_key=api_key.strip())
            heuristics_summary = json.dumps(heuristic_signals, indent=2)
            prompt = f"""
Input Type: {input_type}
Content to Analyze:
---
{content}
---

Heuristics Detected by Rules:
- Heuristic Risk Score: {heuristic_score}
- Heuristic Signals:
{heuristics_summary}

Please analyze this input and provide the final risk score, status classification, merged warning signals, and your detailed AI report in markdown.
"""
            raw_text = ""
            if hasattr(client, "interactions"):
                try:
                    interaction = client.interactions.create(
                        model="models/gemini-3.6-flash", input=prompt, system_instruction=SYSTEM_INSTRUCTION,
                        response_mime_type="application/json", response_schema=LlmPhishingAnalysisSchema,
                    )
                    raw_text = getattr(interaction, "output_text", "") or getattr(interaction, "text", "") or str(interaction)
                except Exception:
                    logger.warning("Gemini interactions request failed; using compatibility API.")
                    response = client.models.generate_content(
                        model="models/gemini-3.6-flash", contents=prompt,
                        config=types.GenerateContentConfig(
                            response_mime_type="application/json", response_schema=LlmPhishingAnalysisSchema,
                            system_instruction=SYSTEM_INSTRUCTION, temperature=0.2,
                        ),
                    )
                    raw_text = response.text
            else:
                response = client.models.generate_content(
                    model="models/gemini-3.6-flash", contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json", response_schema=LlmPhishingAnalysisSchema,
                        system_instruction=SYSTEM_INSTRUCTION, temperature=0.2,
                    ),
                )
                raw_text = response.text
            clean_text = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw_text.strip(), flags=re.IGNORECASE)
            result_json = json.loads(clean_text)
            existing_ids = {sig["id"] for sig in result_json.get("phishing_signals", [])}
            merged_signals = list(result_json.get("phishing_signals", []))
            for sig in heuristic_signals:
                if sig["id"] not in existing_ids:
                    merged_signals.append(sig)
                    existing_ids.add(sig["id"])
            llm_score = max(0, min(100, int(result_json.get("risk_score", 0))))
            final_score = max(heuristic_score, llm_score)
            final_status = "danger" if final_score >= 70 else "warning" if final_score >= 30 else "safe"
            result = {
                "risk_score": final_score, "status": final_status, "phishing_signals": merged_signals,
                "ai_explanation": result_json.get("ai_explanation", "No explanation generated."),
            }
            await llm_cache.set(cache_key, result)
            return result
        except APIError as e:
            logger.warning("Gemini provider request failed (provider status=%s).", getattr(e, "code", "unknown"))
        except Exception:
            logger.exception("LLM analysis failed without exposing provider response details.")
        return get_fallback_analysis(input_type, content, heuristic_score, heuristic_signals)
