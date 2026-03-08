import httpx
import time
import random
import json
import os

# Gateway URL & Settings
API_URL = "http://localhost:8000/scan/text"
# Uses the exact API key we configured in proxy_server.py
API_KEY = os.environ.get("API_KEY", "your-production-secure-api-key-here")

# Synthetic data pools to mimic realistic hospital EMR payloads
PATIENT_NAMES = ["John Doe", "Jane Smith", "Alice Johnson", "Bob Williams", "Charlie Brown", "Diana Prince", "Evan Wright", "Fiona Gallagher"]
CONDITIONS = ["Type 2 Diabetes", "Hypertension", "Asthma", "High Cholesterol", "Migraine", "Osteoarthritis"]
SSNS = ["123-45-6789", "987-65-4321", "555-44-3333", "111-22-3333"]
DOBS = ["01/15/1980", "11-22-1995", "1975-04-03", "12/05/88"]
EMAILS = ["john.doe@email.com", "jane_s@test.org", "alice.j@health.net", "bob.w@clinic.com"]
MRNS = ["MRN-100234", "MED-889123", "PT-556112"]

def generate_payload():
    """Generates a random, synthetic JSON payload containing medical history and PII."""
    name = random.choice(PATIENT_NAMES)
    condition = random.choice(CONDITIONS)
    
    # Randomly inject PII types to vary risk scores
    notes = f"Patient {name} presented today complaining of symptoms related to {condition}. "
    
    if random.random() > 0.5:
        notes += f"DOB is on file as {random.choice(DOBS)}. "
    if random.random() > 0.7:
        notes += f"Contact email: {random.choice(EMAILS)}. "
    if random.random() > 0.8:
        notes += f"Social Security Number: {random.choice(SSNS)}. "
    if random.random() > 0.6:
        notes += f"File under MRN {random.choice(MRNS)}. "

    # Adding some fake clinical data
    notes += "Prescribed lisinopril 10mg daily. Follow up in 6 months."

    return {
        "text": notes,
        "source": "emr-system",
        "endpoint": "/api/v1/clinical_notes"
    }

def pump_data():
    """Continuously sends fake payloads to the Gateway to generate logs/alerts."""
    print("🚀 Starting Synthetic Test Data Generator...")
    print(f"📡 Target: {API_URL}")
    print("Press Ctrl+C to stop.\n")
    
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
    
    with httpx.Client(timeout=10) as client:
        while True:
            payload = generate_payload()
            try:
                response = client.post(API_URL, headers=headers, json=payload)
                if response.status_code == 200:
                    res_json = response.json()
                    risk = res_json.get("risk_level", "UNKNOWN")
                    entities = res_json.get("entity_count", 0)
                    blocked = "🛑 BLOCKED" if res_json.get("should_block") else "✅ ALLOWED"
                    
                    print(f"[{blocked}] Risk: {risk.ljust(8)} | Entities Found: {entities} | Payload: {payload['text'][:50]}...")
                elif response.status_code == 403:
                    print("❌ Error 403: Forbidden. Check your API_KEY.")
                    break
                else:
                    print(f"⚠️ Unexpected Status {response.status_code}: {response.text}")
            except Exception as e:
                print(f"❌ Connection Error: {e}")
            
            # Sleep a bit to create a realistic traffic stream
            time.sleep(random.uniform(1.0, 3.5))

if __name__ == "__main__":
    pump_data()
