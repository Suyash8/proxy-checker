from celery import Celery
from proxy_checker.checker import check_proxy
import json
import os

# Configure Celery
CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

celery_app = Celery('proxy_checker', broker=CELERY_BROKER_URL, backend=CELERY_RESULT_BACKEND)

@celery_app.task
def process_proxies_task(proxies_data, job_id, callback_url=None):
    results = []
    for proxy_data in proxies_data:
        proxy = proxy_data.get('proxy')
        proxy_type = proxy_data.get('type')
        username = proxy_data.get('username')
        password = proxy_data.get('password')
        target_url = proxy_data.get('target_url')
        user_plan = proxy_data.get('user_plan', 'BASIC') # Default to BASIC if not provided

        if not proxy or not proxy_type:
            results.append({"error": "Missing 'proxy' or 'type' in one of the proxy objects."})
            continue

        result = check_proxy(proxy, proxy_type, username, password, target_url, user_plan)

        # Apply filtering based on user_plan for async results as well
        if user_plan in ['BASIC', 'PRO']:
            result.pop("dns_leak_detected", None)
            result.pop("ssl_verified", None)

        if user_plan in ['BASIC', 'PRO', 'ULTRA']:
            result.pop("reputation_score", None)
            result.pop("blacklisted", None)
            result.pop("threat_type", None)

        results.append(result)

    # In a real application, you would store results in a database
    # For this example, we'll just print them and simulate a callback
    print(f"Job {job_id} completed. Results: {results}")

    if callback_url:
        try:
            import requests
            requests.post(callback_url, json={"job_id": job_id, "status": "completed", "results": results})
        except Exception as e:
            print(f"Error sending callback for job {job_id}: {e}")

    return results
