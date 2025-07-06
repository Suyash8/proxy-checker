import requests
from datetime import datetime

def get_geo_data(ip: str) -> dict:
    """
    Gets the geo-location data for an IP address.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return {}

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
        
        end_time = datetime.now()
        latency_ms = (end_time - start_time).total_seconds() * 1000
        
        data = response.json()
        origin_ip = data.get("origin")
        
        geo_data = get_geo_data(proxy.split(':')[0])
        
        return {
            "status": "alive",
            "latency_ms": round(latency_ms),
            "proxy_type": proxy_type.upper(),
            "country": geo_data.get("country"),
            "anonymous": origin_ip != proxy.split(':')[0],
        }
        
    except requests.exceptions.RequestException as e:
        return {"status": "dead", "error": str(e)}
