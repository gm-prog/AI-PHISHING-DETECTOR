import requests
import json
import sys

BACKEND_URL = "http://127.0.5.1:8000"  # Fallback target
# Or standard localhost
BACKEND_URL = "http://127.0.0.1:8000"

def test_health():
    print("=== Testing Backend Health Endpoint ===")
    try:
        response = requests.get(f"{BACKEND_URL}/api/health")
        if response.status_code == 200:
            print("[OK] Health Check Passed!")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"[FAIL] Health Check Failed: Status Code {response.status_code}")
            sys.exit(1)
    except Exception as e:
        print(f"[FAIL] Failed to connect to backend: {str(e)}")
        print("Please ensure the FastAPI server is running (e.g., via uvicorn app.main:app)")
        sys.exit(1)

def test_analyze():
    print("\n=== Testing Backend Phishing Analysis Endpoint ===")
    payload = {
        "input_type": "url",
        "content": "http://secure-login-paypa1-update.xyz/signin"
    }
    
    try:
        response = requests.post(f"{BACKEND_URL}/api/analyze", json=payload)
        if response.status_code == 200:
            print("[OK] Analysis Request Succeeded!")
            data = response.json()
            print(f"Risk Score: {data['risk_score']}")
            print(f"Threat Class: {data['status']}")
            print(f"Signals Found: {len(data['phishing_signals'])}")
            for sig in data['phishing_signals']:
                print(f"  - [{sig['severity'].upper()}] {sig['title']}: {sig['description']}")
            print("\nAI Explanation Output Preview:")
            print(data['ai_explanation'][:250].encode('cp1252', errors='replace').decode('cp1252') + "...")
        else:
            print(f"[FAIL] Analysis Request Failed: Status Code {response.status_code}")
            print(response.text)
            sys.exit(1)
    except Exception as e:
        print(f"[FAIL] Failed to execute analysis: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    test_health()
    test_analyze()
    print("\n[OK] All backend standalone tests complete!")
