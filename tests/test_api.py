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

# Tests for /check/bulk endpoint
def test_check_bulk_endpoint_valid_payload(client, mocker):
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
    
    proxies_to_check = [
        {'proxy': '1.2.3.4:8080', 'type': 'http'},
        {'proxy': '5.6.7.8:8080', 'type': 'https'}
    ]
    
    response = client.post(
        '/check/bulk',
        json=proxies_to_check,
        headers={'X-RapidAPI-Subscription': 'ULTRA'}
    )
    
    assert response.status_code == 200
    assert isinstance(response.json, list)
    assert len(response.json) == 2
    assert response.json[0]["status"] == "alive"
    assert "reputation_score" not in response.json[0] # Filtered for ULTRA plan

def test_check_bulk_endpoint_gating_basic_plan(client):
    response = client.post(
        '/check/bulk',
        json=[{'proxy': '1.2.3.4:8080', 'type': 'http'}],
        headers={'X-RapidAPI-Subscription': 'BASIC'}
    )
    
    assert response.status_code == 403
    assert response.json == {"error": "Bulk checking requires an ULTRA plan or higher."}

def test_check_bulk_endpoint_gating_pro_plan(client):
    response = client.post(
        '/check/bulk',
        json=[{'proxy': '1.2.3.4:8080', 'type': 'http'}],
        headers={'X-RapidAPI-Subscription': 'PRO'}
    )
    
    assert response.status_code == 403
    assert response.json == {"error": "Bulk checking requires an ULTRA plan or higher."}

def test_check_bulk_endpoint_invalid_json_not_list(client):
    response = client.post(
        '/check/bulk',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'},
        headers={'X-RapidAPI-Subscription': 'ULTRA'}
    )
    
    assert response.status_code == 400
    assert response.json == {"error": "Request body must be a JSON array of proxy objects."}

def test_check_bulk_endpoint_too_many_proxies(client):
    proxies_to_check = [{'proxy': f'1.2.3.{i}:8080', 'type': 'http'} for i in range(101)]
    response = client.post(
        '/check/bulk',
        json=proxies_to_check,
        headers={'X-RapidAPI-Subscription': 'ULTRA'}
    )
    
    assert response.status_code == 400
    assert response.json == {"error": "Maximum 100 proxies allowed per bulk request."}

def test_check_bulk_endpoint_missing_proxy_data_in_list(client, mocker):
    mocker.patch('api.app.check_proxy', return_value={
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True
    })
    
    proxies_to_check = [
        {'proxy': '1.2.3.4:8080', 'type': 'http'},
        {'type': 'https'}, # Missing proxy
        {'proxy': '5.6.7.8:8080'}  # Missing type
    ]
    
    response = client.post(
        '/check/bulk',
        json=proxies_to_check,
        headers={'X-RapidAPI-Subscription': 'ULTRA'}
    )
    
    assert response.status_code == 200
    assert isinstance(response.json, list)
    assert len(response.json) == 3
    assert response.json[0]["status"] == "alive"
    assert response.json[1] == {"error": "Missing 'proxy' or 'type' in one of the proxy objects."}
    assert response.json[2] == {"error": "Missing 'proxy' or 'type' in one of the proxy objects."}

# Tests for /check/async endpoint
def test_check_async_endpoint_gating_basic_plan(client):
    response = client.post(
        '/check/async',
        json={'proxies': [{'proxy': '1.2.3.4:8080', 'type': 'http'}]},
        headers={'X-RapidAPI-Subscription': 'BASIC'}
    )
    
    assert response.status_code == 403
    assert response.json == {"error": "Asynchronous checking requires an ENTERPRISE plan or higher."}

def test_check_async_endpoint_gating_pro_plan(client):
    response = client.post(
        '/check/async',
        json={'proxies': [{'proxy': '1.2.3.4:8080', 'type': 'http'}]},
        headers={'X-RapidAPI-Subscription': 'PRO'}
    )
    
    assert response.status_code == 403
    assert response.json == {"error": "Asynchronous checking requires an ENTERPRISE plan or higher."}

def test_check_async_endpoint_gating_ultra_plan(client):
    response = client.post(
        '/check/async',
        json={'proxies': [{'proxy': '1.2.3.4:8080', 'type': 'http'}]},
        headers={'X-RapidAPI-Subscription': 'ULTRA'}
    )
    
    assert response.status_code == 403
    assert response.json == {"error": "Asynchronous checking requires an ENTERPRISE plan or higher."}

def test_check_async_endpoint_valid_payload(client, mocker):
    mock_delay = mocker.patch('api.app.process_proxies_task.delay')
    
    proxies_to_check = [
        {'proxy': '1.2.3.4:8080', 'type': 'http'},
        {'proxy': '5.6.7.8:8080', 'type': 'https'}
    ]
    
    response = client.post(
        '/check/async',
        json={'proxies': proxies_to_check, 'callback_url': 'http://example.com/callback'},
        headers={'X-RapidAPI-Subscription': 'ENTERPRISE'}
    )
    
    assert response.status_code == 202
    assert "job_id" in response.json
    assert response.json["status"] == "submitted"
    mock_delay.assert_called_once()
    args, kwargs = mock_delay.call_args
    assert len(args[0]) == 2  # Two proxies
    assert args[1] == response.json["job_id"]
    assert args[2] == 'http://example.com/callback'
    assert args[0][0]['user_plan'] == 'ENTERPRISE'

def test_check_async_endpoint_invalid_json_not_list(client):
    response = client.post(
        '/check/async',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'},
        headers={'X-RapidAPI-Subscription': 'ENTERPRISE'}
    )
    
    assert response.status_code == 400
    assert response.json == {"error": "'proxies' must be a non-empty JSON array of proxy objects."}

def test_check_async_endpoint_too_many_proxies(client):
    proxies_to_check = [{'proxy': f'1.2.3.{i}:8080', 'type': 'http'} for i in range(1001)]
    response = client.post(
        '/check/async',
        json={'proxies': proxies_to_check},
        headers={'X-RapidAPI-Subscription': 'ENTERPRISE'}
    )
    
    assert response.status_code == 400
    assert response.json == {"error": "Maximum 1000 proxies allowed per asynchronous request."}

def test_get_async_results_pending(client, mocker):
    mock_async_result = mocker.Mock()
    mock_async_result.state = 'PENDING'
    mocker.patch('api.app.process_proxies_task.AsyncResult', return_value=mock_async_result)

    response = client.get('/check/async/some_job_id')
    assert response.status_code == 200
    assert response.json["job_id"] == "some_job_id"
    assert response.json["status"] == "pending"

def test_get_async_results_completed(client, mocker):
    mock_async_result = mocker.Mock()
    mock_async_result.state = 'SUCCESS'
    mock_async_result.result = [{"status": "alive"}]
    mocker.patch('api.app.process_proxies_task.AsyncResult', return_value=mock_async_result)

    response = client.get('/check/async/some_job_id')
    assert response.status_code == 200
    assert response.json["job_id"] == "some_job_id"
    assert response.json["status"] == "completed"
    assert response.json["results"] == [{"status": "alive"}]

def test_get_async_results_failed(client, mocker):
    mock_async_result = mocker.Mock()
    mock_async_result.state = 'FAILURE'
    mock_async_result.info = Exception("Task failed")
    mocker.patch('api.app.process_proxies_task.AsyncResult', return_value=mock_async_result)

    response = client.get('/check/async/some_job_id')
    assert response.status_code == 200
    assert response.json["job_id"] == "some_job_id"
    assert response.json["status"] == "failed"
    assert response.json["error"] == "Task failed"

def test_get_async_results_csv_success(client, mocker):
    mock_async_result = mocker.Mock()
    mock_async_result.state = 'SUCCESS'
    mock_async_result.result = [
        {"proxy": "1.1.1.1:8080", "status": "alive"},
        {"proxy": "2.2.2.2:8080", "status": "dead"}
    ]
    mocker.patch('api.app.process_proxies_task.AsyncResult', return_value=mock_async_result)

    response = client.get('/check/async/some_job_id/csv')
    assert response.status_code == 200
    assert response.headers["Content-type"] == "text/csv"
    assert response.headers["Content-Disposition"] == "attachment; filename=some_job_id.csv"
    expected_csv = "proxy,status\r\n1.1.1.1:8080,alive\r\n2.2.2.2:8080,dead\r\n"
    assert response.data.decode() == expected_csv

def test_get_async_results_csv_job_not_completed(client, mocker):
    mock_async_result = mocker.Mock()
    mock_async_result.state = 'PENDING'
    mocker.patch('api.app.process_proxies_task.AsyncResult', return_value=mock_async_result)

    response = client.get('/check/async/some_job_id/csv')
    assert response.status_code == 404
    assert response.json == {"error": "Job not completed or no results available."}

def test_get_async_results_csv_no_results(client, mocker):
    mock_async_result = mocker.Mock()
    mock_async_result.state = 'SUCCESS'
    mock_async_result.result = []
    mocker.patch('api.app.process_proxies_task.AsyncResult', return_value=mock_async_result)

    response = client.get('/check/async/some_job_id/csv')
    assert response.status_code == 204

