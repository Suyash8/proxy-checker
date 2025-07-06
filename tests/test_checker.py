import pytest
import requests
from proxy_checker.checker import check_proxy, get_geo_data

# Mock data for successful proxy check
MOCK_SUCCESS_IP_RESPONSE = {"origin": "1.1.1.1"}
MOCK_SUCCESS_GEO_RESPONSE = {"country": "United States"}

# Test case for a successful proxy check
def test_check_proxy_success(mocker):
    mocker.patch('requests.get', side_effect=[
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_IP_RESPONSE),
        mocker.Mock(status_code=200, json=lambda: MOCK_SUCCESS_GEO_RESPONSE)
    ])
    
    proxy = "1.2.3.4:8080"
    proxy_type = "http"
    result = check_proxy(proxy, proxy_type)
    
    assert result["status"] == "alive"
    assert isinstance(result["latency_ms"], int)
    assert result["proxy_type"] == "HTTP"
    assert result["country"] == "United States"
    assert result["anonymous"] == True # Because origin_ip (1.1.1.1) != proxy_ip (1.2.3.4)

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