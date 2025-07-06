import sys
import os

# Add the project root to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, request, jsonify
from proxy_checker.checker import check_proxy

app = Flask(__name__)

@app.route('/check', methods=['POST'])
def check():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    proxy = data.get('proxy')
    proxy_type = data.get('type')

    if not proxy or not proxy_type:
        return jsonify({"error": "Missing 'proxy' or 'type' in request body"}), 400

    result = check_proxy(proxy, proxy_type)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
