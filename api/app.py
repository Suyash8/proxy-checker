import sys
import os

# Add the project root to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import uuid

from flask import Flask, request, jsonify
from proxy_checker.checker import check_proxy
from celery_worker import celery_app, process_proxies_task

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

    # Filter DNS leak and SSL verification if user_plan is BASIC or PRO
    if user_plan in ['BASIC', 'PRO']:
        result.pop("dns_leak_detected", None)
        result.pop("ssl_verified", None)

    # Filter reputation and blacklist data if user_plan is BASIC, PRO, or ULTRA
    if user_plan in ['BASIC', 'PRO', 'ULTRA']:
        result.pop("reputation_score", None)
        result.pop("blacklisted", None)
        result.pop("threat_type", None)

    return jsonify(result)

@app.route('/check/bulk', methods=['POST'])
def check_bulk():
    user_plan = request.headers.get('X-RapidAPI-Subscription', 'BASIC').upper()

    if user_plan in ['BASIC', 'PRO']:
        return jsonify({"error": "Bulk checking requires an ULTRA plan or higher."}), 403

    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json(silent=True)

    if data is None:
        return jsonify({"error": "Invalid JSON"}), 400

    if not isinstance(data, list):
        return jsonify({"error": "Request body must be a JSON array of proxy objects."}), 400

    if len(data) > 100:
        return jsonify({"error": "Maximum 100 proxies allowed per bulk request."}), 400

    results = []
    for proxy_data in data:
        proxy = proxy_data.get('proxy')
        proxy_type = proxy_data.get('type')
        username = proxy_data.get('username')
        password = proxy_data.get('password')
        target_url = proxy_data.get('target_url')

        if not proxy or not proxy_type:
            results.append({"error": "Missing 'proxy' or 'type' in one of the proxy objects."})
            continue

        result = check_proxy(proxy, proxy_type, username, password, target_url, user_plan)

        # Apply filtering based on user_plan for bulk results as well
        if user_plan in ['BASIC', 'PRO']:
            result.pop("dns_leak_detected", None)
            result.pop("ssl_verified", None)

        if user_plan in ['BASIC', 'PRO', 'ULTRA']:
            result.pop("reputation_score", None)
            result.pop("blacklisted", None)
            result.pop("threat_type", None)

        results.append(result)

    return jsonify(results)

@app.route('/check/async', methods=['POST'])
def check_async():
    user_plan = request.headers.get('X-RapidAPI-Subscription', 'BASIC').upper()

    if user_plan in ['BASIC', 'PRO', 'ULTRA']:
        return jsonify({"error": "Asynchronous checking requires an ENTERPRISE plan or higher."}), 403

    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json(silent=True)

    if data is None:
        return jsonify({"error": "Invalid JSON"}), 400

    proxies_to_check = data.get('proxies')
    callback_url = data.get('callback_url')

    if not isinstance(proxies_to_check, list) or not proxies_to_check:
        return jsonify({"error": "'proxies' must be a non-empty JSON array of proxy objects."}), 400

    if len(proxies_to_check) > 1000:
        return jsonify({"error": "Maximum 1000 proxies allowed per asynchronous request."}), 400

    job_id = str(uuid.uuid4())

    # Pass user_plan to the Celery task so filtering can be applied within the worker
    for proxy_data in proxies_to_check:
        proxy_data['user_plan'] = user_plan

    process_proxies_task.delay(proxies_to_check, job_id, callback_url)

    return jsonify({"job_id": job_id, "status": "submitted"}), 202

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
