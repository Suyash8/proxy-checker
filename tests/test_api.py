import pytest
from api.app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_check_endpoint_valid_payload(client, mocker):
    # Mock the check_proxy function to return a successful response
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True,
        "isp": "Some ISP",
        "asn": "AS12345",
        "dns_leak_detected": False,
        "ssl_verified": True,
        "reputation_score": 85,
        "blacklisted": False,
        "threat_type": "none"
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'},
        headers={'X-RapidAPI-Subscription': 'ENTERPRISE'}
    )
    
    assert response.status_code == 200
    assert response.json == {
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True,
        "isp": "Some ISP",
        "asn": "AS12345",
        "dns_leak_detected": False,
        "ssl_verified": True,
        "reputation_score": 85,
        "blacklisted": False,
        "threat_type": "none"
    }

def test_check_endpoint_socks_gating_basic_plan(client):
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'socks5'},
        headers={'X-RapidAPI-Subscription': 'BASIC'}
    )
    
    assert response.status_code == 403
    assert response.json == {"error": "SOCKS proxy support requires a PRO plan or higher."}

def test_check_endpoint_auth_gating_basic_plan(client):
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http', 'username': 'user', 'password': 'password'},
        headers={'X-RapidAPI-Subscription': 'BASIC'}
    )
    
    assert response.status_code == 403
    assert response.json == {"error": "Proxy authentication requires a PRO plan or higher."}

def test_check_endpoint_socks_allowed_pro_plan(client, mocker):
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "SOCKS5",
        "country": "United States",
        "anonymous": True,
        "isp": "Some ISP",
        "asn": "AS12345"
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'socks5'},
        headers={'X-RapidAPI-Subscription': 'PRO'}
    )
    
    assert response.status_code == 200
    assert response.json["proxy_type"] == "SOCKS5"

def test_check_endpoint_auth_allowed_pro_plan(client, mocker):
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True,
        "isp": "Some ISP",
        "asn": "AS12345"
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http', 'username': 'user', 'password': 'password'},
        headers={'X-RapidAPI-Subscription': 'PRO'}
    )
    
    assert response.status_code == 200
    assert response.json["status"] == "alive"

def test_check_endpoint_target_url_passed(client, mocker):
    mock_check_proxy = mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True,
        "isp": "Some ISP",
        "asn": "AS12345"
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http', 'target_url': 'https://example.com'},
        headers={'X-RapidAPI-Subscription': 'PRO'}
    )
    
    assert response.status_code == 200
    mock_check_proxy.assert_called_once_with('1.2.3.4:8080', 'http', None, None, 'https://example.com', 'PRO')

def test_check_endpoint_isp_asn_filtered_basic_plan(client, mocker):
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'},
        headers={'X-RapidAPI-Subscription': 'BASIC'}
    )
    
    assert response.status_code == 200
    assert "isp" not in response.json
    assert "asn" not in response.json

def test_check_endpoint_isp_asn_included_pro_plan(client, mocker):
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True,
        "isp": "Some ISP",
        "asn": "AS12345"
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'},
        headers={'X-RapidAPI-Subscription': 'PRO'}
    )
    
    assert response.status_code == 200
    assert response.json["isp"] == "Some ISP"
    assert response.json["asn"] == "AS12345"

def test_check_endpoint_dns_ssl_filtered_basic_plan(client, mocker):
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'},
        headers={'X-RapidAPI-Subscription': 'BASIC'}
    )
    
    assert response.status_code == 200
    assert "dns_leak_detected" not in response.json
    assert "ssl_verified" not in response.json

def test_check_endpoint_dns_ssl_filtered_pro_plan(client, mocker):
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True,
        "dns_leak_detected": False,
        "ssl_verified": True
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'},
        headers={'X-RapidAPI-Subscription': 'PRO'}
    )
    
    assert response.status_code == 200
    assert "dns_leak_detected" not in response.json
    assert "ssl_verified" not in response.json

def test_check_endpoint_dns_ssl_included_ultra_plan(client, mocker):
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True,
        "dns_leak_detected": False,
        "ssl_verified": True
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'},
        headers={'X-RapidAPI-Subscription': 'ULTRA'}
    )
    
    assert response.status_code == 200
    assert response.json["dns_leak_detected"] == False
    assert response.json["ssl_verified"] == True

def test_check_endpoint_reputation_filtered_basic_plan(client, mocker):
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True,
        "reputation_score": 85,
        "blacklisted": False,
        "threat_type": "none"
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'},
        headers={'X-RapidAPI-Subscription': 'BASIC'}
    )
    
    assert response.status_code == 200
    assert "reputation_score" not in response.json
    assert "blacklisted" not in response.json
    assert "threat_type" not in response.json

def test_check_endpoint_reputation_filtered_pro_plan(client, mocker):
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True,
        "reputation_score": 85,
        "blacklisted": False,
        "threat_type": "none"
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'},
        headers={'X-RapidAPI-Subscription': 'PRO'}
    )
    
    assert response.status_code == 200
    assert "reputation_score" not in response.json
    assert "blacklisted" not in response.json
    assert "threat_type" not in response.json

def test_check_endpoint_reputation_filtered_ultra_plan(client, mocker):
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True,
        "reputation_score": 85,
        "blacklisted": False,
        "threat_type": "none"
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'},
        headers={'X-RapidAPI-Subscription': 'ULTRA'}
    )
    
    assert response.status_code == 200
    assert "reputation_score" not in response.json
    assert "blacklisted" not in response.json
    assert "threat_type" not in response.json

def test_check_endpoint_reputation_included_enterprise_plan(client, mocker):
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True,
        "reputation_score": 85,
        "blacklisted": False,
        "threat_type": "none"
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'},
        headers={'X-RapidAPI-Subscription': 'ENTERPRISE'}
    )
    
    assert response.status_code == 200
    assert response.json["reputation_score"] == 85
    assert response.json["blacklisted"] == False
    assert response.json["threat_type"] == "none"

def test_check_endpoint_no_plan_header_defaults_to_basic(client, mocker):
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'}
    )
    
    assert response.status_code == 200
    assert "isp" not in response.json
    assert "asn" not in response.json
    assert "dns_leak_detected" not in response.json
    assert "ssl_verified" not in response.json
    assert "reputation_score" not in response.json
    assert "blacklisted" not in response.json
    assert "threat_type" not in response.json

def test_check_endpoint_invalid_plan_header_defaults_to_basic(client, mocker):
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'},
        headers={'X-RapidAPI-Subscription': 'INVALID_PLAN'}
    )
    
    assert response.status_code == 200
    assert "isp" not in response.json
    assert "asn" not in response.json
    assert "dns_leak_detected" not in response.json
    assert "ssl_verified" not in response.json
    assert "reputation_score" not in response.json
    assert "blacklisted" not in response.json
    assert "threat_type" not in response.json



def test_check_endpoint_missing_proxy(client):
    response = client.post(
        '/check',
        json={'type': 'http'}
    )
    
    assert response.status_code == 400
    assert response.json == {"error": "Missing 'proxy' or 'type' in request body"}

def test_check_endpoint_missing_type(client):
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080'}
    )
    
    assert response.status_code == 400
    assert response.json == {"error": "Missing 'proxy' or 'type' in request body"}

def test_check_endpoint_empty_json(client):
    response = client.post(
        '/check',
        json={}
    )
    
    assert response.status_code == 400
    assert response.json == {"error": "Missing 'proxy' or 'type' in request body"}

def test_check_endpoint_invalid_json(client):
    response = client.post(
        '/check',
        data="invalid json",
        content_type='application/json'
    )
    
    assert response.status_code == 400
    assert response.json == {"error": "Invalid JSON"}

def test_check_endpoint_get_method(client):
    response = client.get('/check')
    assert response.status_code == 405 # Method Not Allowed
