import sys
import os

# Add the project root to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, request, jsonify
from proxy_checker.checker import check_proxy

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok"}), 200

@app.route('/check', methods=['POST'])
def check():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json(silent=True)

    if data is None:
        return jsonify({"error": "Invalid JSON"}), 400

    proxy = data.get('proxy')
    proxy_type = data.get('type')
    username = data.get('username')
    password = data.get('password')
    target_url = data.get('target_url')

    if not proxy or not proxy_type:
        return jsonify({"error": "Missing 'proxy' or 'type' in request body"}), 400

    user_plan = request.headers.get('X-RapidAPI-Subscription', 'BASIC').upper()

    # SOCKS proxy support gating
    if user_plan == 'BASIC' and proxy_type in ['socks4', 'socks5']:
        return jsonify({"error": "SOCKS proxy support requires a PRO plan or higher."}), 403

    # Proxy authentication gating
    if user_plan == 'BASIC' and (username or password):
        return jsonify({"error": "Proxy authentication requires a PRO plan or higher."}), 403

    result = check_proxy(proxy, proxy_type, username, password, target_url, user_plan)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
