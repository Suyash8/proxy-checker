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
        "anonymous": True
    })
    
    response = client.post(
        '/check',
        json={'proxy': '1.2.3.4:8080', 'type': 'http'}
    )
    
    assert response.status_code == 200
    assert response.json == {
        "status": "alive",
        "latency_ms": 100,
        "proxy_type": "HTTP",
        "country": "United States",
        "anonymous": True
    }

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
