# Proxy Checker API

This is a simple API for checking the status, latency, country, and anonymity of proxy servers.

## Features

*   Check proxy status (alive/dead)
*   Measure proxy latency
*   Determine proxy's country, ISP, and ASN using a Geo-IP API
*   Detect proxy anonymity
*   Supports HTTP/HTTPS/SOCKS4/SOCKS5 proxies
*   Supports proxy authentication
*   DNS Leak detection
*   SSL Certificate verification
*   Proxy Reputation and Blacklist checks

## API Usage

The API exposes a single endpoint: `/check`

### `POST /check`

Checks the status of a given proxy with various optional enhancements based on the RapidAPI subscription plan.

**Request Headers:**

*   `X-RapidAPI-Subscription` (string, optional): Your RapidAPI subscription plan. Valid values: `BASIC`, `PRO`, `ULTRA`, `ENTERPRISE`. Defaults to `BASIC` if not provided.

**Request Body (JSON):**

```json
{
    "proxy": "<proxy_address>:<port>",
    "type": "<proxy_type>",
    "username": "<username>",       (optional, requires PRO plan or higher)
    "password": "<password>",       (optional, requires PRO plan or higher)
    "target_url": "<url>"           (optional, defaults to httpbin.org/ip)
}
```

*   `proxy` (string, required): The proxy address and port (e.g., `123.45.67.89:8080`).
*   `type` (string, required): The proxy type (e.g., `http`, `https`, `socks4`, `socks5`).
*   `username` (string, optional): Username for authenticated proxies. Requires `PRO` plan or higher.
*   `password` (string, optional): Password for authenticated proxies. Requires `PRO` plan or higher.
*   `target_url` (string, optional): A custom URL to check the proxy against. Defaults to `httpbin.org/ip`.

**Example Request (using curl):**

```bash
# Basic Plan Request
curl -X POST -H "Content-Type: application/json" -d '{"proxy": "13.57.11.118:3128", "type": "http"}' http://127.0.0.1:5000/check

# PRO Plan Request (with SOCKS5 and authentication)
curl -X POST -H "Content-Type: application/json" -H "X-RapidAPI-Subscription: PRO" -d '{"proxy": "1.2.3.4:1080", "type": "socks5", "username": "myuser", "password": "mypass"}' http://127.0.0.1:5000/check

# ENTERPRISE Plan Request (with custom target URL)
curl -X POST -H "Content-Type: application/json" -H "X-RapidAPI-Subscription: ENTERPRISE" -d '{"proxy": "5.6.7.8:8080", "type": "http", "target_url": "https://www.google.com"}' http://127.0.0.1:5000/check
```

**Example Success Response (JSON):**

```json
{
    "status": "alive",
    "latency_ms": 321,
    "country": "United States",
    "proxy_type": "HTTP",
    "anonymous": true,
    "isp": "Some ISP Name",            (PRO plan or higher)
    "asn": "AS12345 Some ASN Name",      (PRO plan or higher)
    "dns_leak_detected": false,        (ULTRA plan or higher)
    "ssl_verified": true,              (ULTRA plan or higher)
    "reputation_score": 85,            (ENTERPRISE plan or higher)
    "blacklisted": false,              (ENTERPRISE plan or higher)
    "threat_type": "none"              (ENTERPRISE plan or higher)
}
```

**Example Forbidden Response (JSON - due to plan limitations):**

```json
{
    "error": "SOCKS proxy support requires a PRO plan or higher."
}
```

**Example Dead Proxy Response (JSON):**

```json
{
    "status": "dead",
    "error": "ConnectionError: HTTPConnectionPool(...)"
}
```

**Example Bad Request Response (JSON - Missing fields):**

```bash
curl -X POST -H "Content-Type: application/json" -d '{"type": "http"}' http://127.0.0.1:5000/check
```

```json
{
    "error": "Missing 'proxy' or 'type' in request body"
}
```

**Example Bad Request Response (JSON - Invalid JSON):**

```bash
curl -X POST -H "Content-Type: application/json" -d 'invalid json' http://127.0.0.1:5000/check
```

```json
{
    "error": "Invalid JSON"
}
```

## Local Setup

1.  **Clone the repository:**

    ```bash
    git clone <repository_url>
    cd proxy-checker
    ```

2.  **Create and activate a virtual environment:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the Flask application:**

    ```bash
    python3 api/app.py
    # The API will be available at http://127.0.0.1:5000
    ```

## Running Tests

To run the unit and integration tests:

```bash
pytest
```

## Deployment with Docker

1.  **Build the Docker image:**

    ```bash
    docker build -t proxy-checker .
    ```

2.  **Run the Docker container:**

    ```bash
    docker run -p 5000:5000 proxy-checker
    ```

    The API will be available at `http://localhost:5000`.
