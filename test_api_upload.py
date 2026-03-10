import requests
import json
import sys

# Ensure UTF-8 output for Windows terminals
sys.stdout.reconfigure(encoding='utf-8')

API_URL = "http://localhost:8000/scan/document"
FILE_PATH = r"C:\Users\pc\Downloads\Healthcare Privacy Firewall\pii_phi_test_dataset.xlsx"

print(f"Uploading {FILE_PATH} to {API_URL}...")

try:
    with open(FILE_PATH, "rb") as f:
        files = {"file": (FILE_PATH, f, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
        # Use the dummy api key from .env.example if needed, but endpoint might be open for testing
        headers = {"x-api-key": "your-production-secure-api-key-here"}
        
        response = requests.post(API_URL, files=files, headers=headers)
        
    print(f"\nStatus Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print("\n--- API Scan Results ---")
        print(f"Entities Found: {data.get('entity_count', 0)}")
        print(f"Risk Score: {data.get('risk', {}).get('score', 0)}")
        print(f"Risk Level: {data.get('risk', {}).get('level', 'unknown').upper()}")
        print("\nRecommendations based on scan:")
        for rec in data.get("risk", {}).get("recommendations", []):
            print(f" - {rec}")
            
        print("\nFirst 5 Detections:")
        for i, det in enumerate(data.get("detections", [])[:5]):
            print(f" [{i+1}] {det.get('entity_type')} (Confidence: {det.get('score')})")
            
        print("\nMasked Text Snippet (first 500 chars):")
        print("-" * 40)
        print(data.get("masked_text", "")[:500] + "...")
        print("-" * 40)
        
    else:
        print("\nError Requesting API:")
        print(response.text)

except Exception as e:
    print(f"Error connecting to API: {e}")
