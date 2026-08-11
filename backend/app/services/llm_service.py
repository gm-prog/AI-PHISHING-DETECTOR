from google import genai
from google.genai import types
from google.genai.errors import APIError
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import json
import logging
import traceback

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
    """
    Validates a Gemini API key by making a lightweight query.
    Returns {"valid": True} or {"valid": False, "error": str} with descriptive error details.
    """
    if not api_key or not api_key.strip():
        return {"valid": False, "error": "API key is empty."}
        
    try:
        client = genai.Client(api_key=api_key.strip())
        # Make a tiny lightweight call to check validity
        client.models.generate_content(
            model='gemini-2.0-flash',
            contents='Verify connection test.'
        )
        logger.info("[SECURE] Gemini API key verified successfully.")
        return {"valid": True}
    except APIError as e:
        error_msg = f"Gemini API authentication failed: {e.message} (Status Code: {e.code})"
        logger.error(f"[API ERROR] {error_msg}")
        return {"valid": False, "error": e.message}
    except Exception as e:
        error_msg = f"Network or unexpected error verifying API key: {str(e)}"
        logger.error(f"[SYSTEM ERROR] {error_msg}\n{traceback.format_exc()}")
        return {"valid": False, "error": str(e)}

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

def analyze_with_llm(
    input_type: str,
    content: str,
    api_key: Optional[str],
    heuristic_score: int,
    heuristic_signals: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Calls the Gemini API to analyze the phishing context.
    Falls back to heuristic reporting if the API call fails or key is missing.
    """
    if not api_key:
        logger.info("Skipping LLM analysis: No API key provided.")
        return get_fallback_analysis(input_type, content, heuristic_score, heuristic_signals)
        
    try:
        # Initialize Google GenAI client
        client = genai.Client(api_key=api_key.strip())
        
        # Prepare the query content
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
        
        # Run content generation with strict response schema mapping
        response = client.models.generate_content(
            model='gemini-2.0-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=LlmPhishingAnalysisSchema,
                system_instruction=SYSTEM_INSTRUCTION,
                temperature=0.2
            )
        )
        
        # Parse the JSON response
        import re
        raw_text = response.text
        # Strip potential markdown code blocks
        clean_text = re.sub(r'^```(?:json)?\s*|\s*```$', '', raw_text.strip(), flags=re.IGNORECASE)
        result_json = json.loads(clean_text)
        
        # Merge heuristic signals and AI signals (avoiding duplicate IDs)
        existing_ids = {sig["id"] for sig in result_json.get("phishing_signals", [])}
        merged_signals = list(result_json.get("phishing_signals", []))
        
        for sig in heuristic_signals:
            if sig["id"] not in existing_ids:
                merged_signals.append(sig)
                existing_ids.add(sig["id"])
                
        # Recalculate or average risk score based on both heuristic and LLM scores
        llm_score = result_json.get("risk_score", 0)
        final_score = max(heuristic_score, llm_score)
        
        # Set final status
        final_status = "safe"
        if final_score >= 70:
            final_status = "danger"
        elif final_score >= 30:
            final_status = "warning"
            
        return {
            "risk_score": final_score,
            "status": final_status,
            "phishing_signals": merged_signals,
            "ai_explanation": result_json.get("ai_explanation", "No explanation generated.")
        }
        
    except APIError as e:
        logger.error(f"[GEMINI API ERROR] Authentication/Rate limit fail code={e.code}: {e.message}")
        return get_fallback_analysis(input_type, content, heuristic_score, heuristic_signals)
    except Exception as e:
        logger.error(f"[LLM SERVICE FAILED] Unexpected error querying Gemini: {str(e)}\n{traceback.format_exc()}")
        return get_fallback_analysis(input_type, content, heuristic_score, heuristic_signals)
