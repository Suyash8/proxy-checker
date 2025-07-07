import requests
import ssl
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

def dns_leak_test(proxies: dict) -> bool:
    """
    Performs a DNS leak test through the proxy.
    Returns True if a DNS leak is detected, False otherwise.
    """
    try:
        # Use a known DNS leak test service that returns JSON
        response = requests.get("https://ipleak.net/json/", proxies=proxies, timeout=5)
        response.raise_for_status()
        data = response.json()
        # Check if the reported IP is different from the proxy's IP
        # This is a simplified check, a more robust one would compare DNS server IPs
        if "ip" in data and data["ip"] != proxies["http"].split('//')[1].split(':')[0]:
            return True
        return False
    except requests.exceptions.RequestException:
        return True  # Assume leak or failure if test cannot be performed

def ssl_verification(proxy_url: str) -> bool:
    """
    Performs a basic SSL certificate verification for HTTPS proxies.
    Returns True if SSL certificate is valid, False otherwise.
    """
    try:
        # Attempt to connect to a well-known HTTPS site through the proxy
        # and verify SSL certificate
        requests.get("https://www.google.com", proxies={"https": proxy_url}, timeout=5, verify=False)
        return True
    except requests.exceptions.SSLError:
        return False
    except requests.exceptions.RequestException:
        return False

def get_reputation_data(ip: str) -> dict:
    """
    Placeholder for fetching proxy reputation and blacklist data.
    For initial implementation, returns dummy data.
    """
    # In a real scenario, this would call an external API (e.g., IPQualityScore)
    # For now, return dummy data
    return {
        "reputation_score": 85,  # Dummy score out of 100
        "blacklisted": False,    # Dummy blacklist status
        "threat_type": "none"    # Dummy threat type
    }

def check_proxy(proxy: str, proxy_type: str, username: str = None, password: str = None, target_url: str = None, user_plan: str = "BASIC") -> dict:
    """
    Checks the status of a proxy with enhanced features.
    """
    if proxy_type in ['http', 'https']:
        proxy_url = f'{proxy_type}://{proxy}'
    elif proxy_type in ['socks4', 'socks5']:
        proxy_url = f'{proxy_type}://{proxy}'
    else:
        raise ValueError(f"Unsupported proxy type: {proxy_type}")

    proxies = {
        "http": proxy_url,
        "https": proxy_url
    }

    auth = (username, password) if username and password else None
    
    # Use default target_url if none is provided
    effective_target_url = target_url if target_url is not None else "http://httpbin.org/ip"

    start_time = datetime.now()

    try:
        response = requests.get(effective_target_url, proxies=proxies, auth=auth, timeout=5)
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

        # Add DNS leak and SSL verification if user_plan is not BASIC or PRO
        if user_plan not in ['BASIC', 'PRO']:
            result["dns_leak_detected"] = dns_leak_test(proxies)
            result["ssl_verified"] = ssl_verification(proxies["https"])

        # Add reputation and blacklist check if user_plan is not BASIC, PRO, or ULTRA
        if user_plan not in ['BASIC', 'PRO', 'ULTRA']:
            reputation_data = get_reputation_data(proxy_ip)
            result["reputation_score"] = reputation_data.get("reputation_score")
            result["blacklisted"] = reputation_data.get("blacklisted")
            result["threat_type"] = reputation_data.get("threat_type")

        return result

    except requests.exceptions.Timeout as e:
        return {"status": "dead", "error": f"Timeout: {str(e)}"}
    except requests.exceptions.ConnectionError as e:
        return {"status": "dead", "error": f"ConnectionError: {str(e)} (Note: SOCKS proxies require PySocks library)"}
    except requests.exceptions.HTTPError as e:
        return {"status": "dead", "error": f"HTTPError: {str(e)}"}
    except requests.exceptions.SSLError as e:
        return {"status": "dead", "error": f"SSLError: {str(e)}"}
    except ValueError as e:
        if "Cannot set verify_mode to CERT_NONE when check_hostname is enabled." in str(e):
            return {"status": "dead", "error": f"SSL Configuration Error: {str(e)}. This often happens with HTTPS proxies that have invalid or self-signed certificates."}
        return {"status": "dead", "error": f"ValueError: {str(e)}"}
    except requests.exceptions.RequestException as e:
        return {"status": "dead", "error": f"RequestException: {str(e)}"}
