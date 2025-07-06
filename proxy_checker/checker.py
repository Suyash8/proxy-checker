import requests
from datetime import datetime

def check_proxy(proxy: str, proxy_type: str) -> dict:
    """
    Checks the status of a proxy.
    """
    proxy_url = f'{proxy_type}://{proxy}'
    target_url = "http://httpbin.org/ip"
    
    start_time = datetime.now()
    
    try:
        response = requests.get(target_url, proxies={"http": proxy_url, "https": proxy_url}, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return {"status": "dead", "error": str(e)}
    
    end_time = datetime.now()
    latency_ms = (end_time - start_time).total_seconds() * 1000
    
    return {
        "status": "alive",
        "latency_ms": round(latency_ms),
        "proxy_type": proxy_type.upper(),
    }
