import requests
from datetime import datetime

def get_geo_data(ip: str) -> dict:
    """
    Gets the geo-location data for an IP address, including ISP and ASN.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=country,isp,as")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return {}

def check_proxy(proxy: str, proxy_type: str, username: str = None, password: str = None, target_url: str = "http://httpbin.org/ip", user_plan: str = "BASIC") -> dict:
    """
    Checks the status of a proxy with enhanced features.
    """
    proxies = {
        "http": f'{proxy_type}://{proxy}',
        "https": f'{proxy_type}://{proxy}'
    }

    auth = (username, password) if username and password else None

    start_time = datetime.now()

    try:
        response = requests.get(target_url, proxies=proxies, auth=auth, timeout=5)
        response.raise_for_status()

        end_time = datetime.now()
        latency_ms = (end_time - start_time).total_seconds() * 1000

        data = response.json()
        origin_ip = data.get("origin")

        proxy_ip = proxy.split(':')[0]
        geo_data = get_geo_data(proxy_ip)

        result = {
            "status": "alive",
            "latency_ms": round(latency_ms),
            "proxy_type": proxy_type.upper(),
            "country": geo_data.get("country"),
            "anonymous": origin_ip != proxy_ip,
        }

        # Add ISP and ASN if user_plan is not BASIC
        if user_plan != 'BASIC':
            result["isp"] = geo_data.get("isp")
            result["asn"] = geo_data.get("as")

        return result

    except requests.exceptions.Timeout as e:
        return {"status": "dead", "error": f"Timeout: {str(e)}"}
    except requests.exceptions.ConnectionError as e:
        return {"status": "dead", "error": f"ConnectionError: {str(e)} (Note: SOCKS proxies require PySocks library)"}
    except requests.exceptions.HTTPError as e:
        return {"status": "dead", "error": f"HTTPError: {str(e)}"}
    except requests.exceptions.RequestException as e:
        return {"status": "dead", "error": f"RequestException: {str(e)}"}
