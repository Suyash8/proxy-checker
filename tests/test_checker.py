import pytest
import requests
from proxy_checker.checker import check_proxy, get_geo_data, dns_leak_test, ssl_verification

# Mock data for successful proxy check
MOCK_SUCCESS_IP_RESPONSE = {"origin": "1.1.1.1"}
MOCK_SUCCESS_GEO_RESPONSE = {"country": "United States", "isp": "Some ISP", "as": "AS12345 Some ASN"}

# Test case for a successful proxy check
def test_check_proxy_success_enterprise_plan(mocker):
    mocker.patch('requests.get', side_effect=[
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_IP_RESPONSE),
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_GEO_RESPONSE),
        mocker.Mock(status_code=200, json=lambda: {"ip": "1.2.3.4"}), # For dns_leak_test
        mocker.Mock(status_code=200) # For ssl_verification
    ])
    
    proxy = "1.2.3.4:8080"
    proxy_type = "http"
    result = check_proxy(proxy, proxy_type, user_plan="ENTERPRISE")
    
    assert result["status"] == "alive"
    assert isinstance(result["latency_ms"], int)
    assert result["proxy_type"] == "HTTP"
    assert result["country"] == "United States"
    assert result["anonymous"] == True # Because origin_ip (1.1.1.1) != proxy_ip (1.2.3.4)
    assert result["isp"] == "Some ISP"
    assert result["asn"] == "AS12345 Some ASN"
    assert result["dns_leak_detected"] == False
    assert result["ssl_verified"] == True
    assert result["reputation_score"] == 85
    assert result["blacklisted"] == False
    assert result["threat_type"] == "none"

def test_check_proxy_success_basic_plan(mocker):
    mocker.patch('requests.get', side_effect=[
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_IP_RESPONSE),
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_GEO_RESPONSE)
    ])
    
    proxy = "1.2.3.4:8080"
    proxy_type = "http"
    result = check_proxy(proxy, proxy_type, user_plan="BASIC")
    
    assert result["status"] == "alive"
    assert isinstance(result["latency_ms"], int)
    assert result["proxy_type"] == "HTTP"
    assert result["country"] == "United States"
    assert result["anonymous"] == True
    assert "isp" not in result
    assert "asn" not in result
    assert "dns_leak_detected" not in result
    assert "ssl_verified" not in result
    assert "reputation_score" not in result
    assert "blacklisted" not in result
    assert "threat_type" not in result

def test_check_proxy_success_pro_plan(mocker):
    mocker.patch('requests.get', side_effect=[
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_IP_RESPONSE),
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_GEO_RESPONSE)
    ])
    
    proxy = "1.2.3.4:8080"
    proxy_type = "http"
    result = check_proxy(proxy, proxy_type, user_plan="PRO")
    
    assert result["status"] == "alive"
    assert isinstance(result["latency_ms"], int)
    assert result["proxy_type"] == "HTTP"
    assert result["country"] == "United States"
    assert result["anonymous"] == True
    assert result["isp"] == "Some ISP"
    assert result["asn"] == "AS12345 Some ASN"
    assert "dns_leak_detected" not in result
    assert "ssl_verified" not in result
    assert "reputation_score" not in result
    assert "blacklisted" not in result
    assert "threat_type" not in result

def test_check_proxy_success_ultra_plan(mocker):
    mocker.patch('requests.get', side_effect=[
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_IP_RESPONSE),
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_GEO_RESPONSE),
        mocker.Mock(status_code=200, json=lambda: {"ip": "1.2.3.4"}), # For dns_leak_test
        mocker.Mock(status_code=200) # For ssl_verification
    ])
    
    proxy = "1.2.3.4:8080"
    proxy_type = "http"
    result = check_proxy(proxy, proxy_type, user_plan="ULTRA")
    
    assert result["status"] == "alive"
    assert isinstance(result["latency_ms"], int)
    assert result["proxy_type"] == "HTTP"
    assert result["country"] == "United States"
    assert result["anonymous"] == True
    assert result["isp"] == "Some ISP"
    assert result["asn"] == "AS12345 Some ASN"
    assert result["dns_leak_detected"] == False
    assert result["ssl_verified"] == True
    assert "reputation_score" not in result
    assert "blacklisted" not in result
    assert "threat_type" not in result

def test_check_proxy_success_enterprise_plan(mocker):
    mocker.patch('requests.get', side_effect=[
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_IP_RESPONSE),
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_GEO_RESPONSE),
        mocker.Mock(status_code=200, json=lambda: {"ip": "1.2.3.4"}), # For dns_leak_test
        mocker.Mock(status_code=200) # For ssl_verification
    ])
    
    proxy = "1.2.3.4:8080"
    proxy_type = "http"
    result = check_proxy(proxy, proxy_type, user_plan="ENTERPRISE")
    
    assert result["status"] == "alive"
    assert isinstance(result["latency_ms"], int)
    assert result["proxy_type"] == "HTTP"
    assert result["country"] == "United States"
    assert result["anonymous"] == True
    assert result["isp"] == "Some ISP"
    assert result["asn"] == "AS12345 Some ASN"
    assert result["dns_leak_detected"] == False
    assert result["ssl_verified"] == True
    assert result["reputation_score"] == 85
    assert result["blacklisted"] == False
    assert result["threat_type"] == "none"

# Test case for proxy timeout
def test_check_proxy_timeout(mocker):
    mocker.patch('requests.get', side_effect=requests.exceptions.Timeout)
    
    proxy = "1.2.3.4:8080"
    proxy_type = "http"
    result = check_proxy(proxy, proxy_type)
    
    assert result["status"] == "dead"
    assert "Timeout" in result["error"]

# Test case for connection error
def test_check_proxy_connection_error(mocker):
    mocker.patch('requests.get', side_effect=requests.exceptions.ConnectionError)
    
    proxy = "1.2.3.4:8080"
    proxy_type = "http"
    result = check_proxy(proxy, proxy_type)
    
    assert result["status"] == "dead"
    assert "ConnectionError" in result["error"]

# Test case for HTTP error (e.g., 404, 500)
def test_check_proxy_http_error(mocker):
    mocker.patch('requests.get', side_effect=requests.exceptions.HTTPError)
    
    proxy = "1.2.3.4:8080"
    proxy_type = "http"
    result = check_proxy(proxy, proxy_type)
    
    assert result["status"] == "dead"
    assert "HTTPError" in result["error"]

# Test case for get_geo_data function
def test_get_geo_data(mocker):
    mocker.patch('requests.get', return_value=mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_GEO_RESPONSE))
    
    ip = "8.8.8.8"
    result = get_geo_data(ip)
    
    assert result["country"] == "United States"
    assert result["isp"] == "Some ISP"
    assert result["as"] == "AS12345 Some ASN"

def test_get_geo_data_failure(mocker):
    mocker.patch('requests.get', side_effect=requests.exceptions.RequestException)
    
    ip = "invalid_ip"
    result = get_geo_data(ip)
    
    assert result == {}

def test_check_proxy_anonymous_true(mocker):
    mocker.patch('requests.get', side_effect=[
        mocker.Mock(status_code=200, json=lambda: {"origin": "5.6.7.8"}), # Different IP
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_GEO_RESPONSE)
    ])
    
    proxy = "1.2.3.4:8080"
    proxy_type = "http"
    result = check_proxy(proxy, proxy_type)
    
    assert result["anonymous"] == True

def test_check_proxy_anonymous_false(mocker):
    mocker.patch('requests.get', side_effect=[
        mocker.Mock(status_code=200, json=lambda: {"origin": "1.2.3.4"}), # Same IP
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_GEO_RESPONSE)
    ])
    
    proxy = "1.2.3.4:8080"
    proxy_type = "http"
    result = check_proxy(proxy, proxy_type)
    
    assert result["anonymous"] == False

def test_check_proxy_type_https(mocker):
    mocker.patch('requests.get', side_effect=[
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_IP_RESPONSE),
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_GEO_RESPONSE)
    ])
    
    proxy = "1.2.3.4:8080"
    proxy_type = "https"
    result = check_proxy(proxy, proxy_type)
    
    assert result["proxy_type"] == "HTTPS"

def test_check_proxy_with_authentication(mocker):
    mocker.patch('requests.get', side_effect=[
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_IP_RESPONSE),
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_GEO_RESPONSE)
    ])
    
    proxy = "1.2.3.4:8080"
    proxy_type = "http"
    username = "testuser"
    password = "testpass"
    result = check_proxy(proxy, proxy_type, username, password, user_plan="PRO")
    
    assert result["status"] == "alive"
    assert isinstance(result["latency_ms"], int)
    assert result["proxy_type"] == "HTTP"

def test_check_proxy_with_custom_target_url(mocker):
    mocker.patch('requests.get', side_effect=[
        mocker.Mock(status_code=200, json=lambda: {"origin": "1.1.1.1"}),
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_GEO_RESPONSE)
    ])
    
    proxy = "1.2.3.4:8080"
    proxy_type = "http"
    target_url = "https://www.google.com"
    result = check_proxy(proxy, proxy_type, target_url=target_url, user_plan="PRO")
    
    assert result["status"] == "alive"
    assert isinstance(result["latency_ms"], int)
    assert result["proxy_type"] == "HTTP"

def test_check_proxy_socks5(mocker):
    mocker.patch('requests.get', side_effect=[
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_IP_RESPONSE),
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_GEO_RESPONSE)
    ])
    
    proxy = "1.2.3.4:8080"
    proxy_type = "socks5"
    result = check_proxy(proxy, proxy_type, user_plan="PRO")
    
    assert result["proxy_type"] == "SOCKS5"

def test_check_proxy_socks4(mocker):
    mocker.patch('requests.get', side_effect=[
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_IP_RESPONSE),
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_GEO_RESPONSE)
    ])
    
    proxy = "1.2.3.4:8080"
    proxy_type = "socks4"
    result = check_proxy(proxy, proxy_type, user_plan="PRO")
    
    assert result["proxy_type"] == "SOCKS4"

def test_dns_leak_test_no_leak(mocker):
    mocker.patch('requests.get', return_value=mocker.Mock(status_code=200, json=lambda: {"ip": "1.2.3.4"}))
    proxies = {"http": "http://1.2.3.4:8080"}
    assert dns_leak_test(proxies) == False

def test_dns_leak_test_leak(mocker):
    mocker.patch('requests.get', return_value=mocker.Mock(status_code=200, json=lambda: {"ip": "5.6.7.8"}))
    proxies = {"http": "http://1.2.3.4:8080"}
    assert dns_leak_test(proxies) == True

def test_dns_leak_test_failure(mocker):
    mocker.patch('requests.get', side_effect=requests.exceptions.RequestException)
    proxies = {"http": "http://1.2.3.4:8080"}
    assert dns_leak_test(proxies) == True

def test_ssl_verification_success(mocker):
    mocker.patch('requests.get', return_value=mocker.Mock(status_code=200))
    proxy_url = "https://1.2.3.4:8080"
    assert ssl_verification(proxy_url) == True

def test_ssl_verification_failure(mocker):
    mocker.patch('requests.get', side_effect=requests.exceptions.SSLError)
    proxy_url = "https://1.2.3.4:8080"
    assert ssl_verification(proxy_url) == False

def test_ssl_verification_request_exception(mocker):
    mocker.patch('requests.get', side_effect=requests.exceptions.RequestException)
    proxy_url = "https://1.2.3.4:8080"
    assert ssl_verification(proxy_url) == False