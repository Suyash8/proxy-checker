# Proxy Checker API

This is a simple API for checking the status, latency, country, and anonymity of proxy servers.

## Features

*   Check proxy status (alive/dead)
*   Measure proxy latency
*   Determine proxy's country using a Geo-IP API
*   Detect proxy anonymity
*   Supports HTTP/HTTPS proxies

## API Usage

The API exposes a single endpoint: `/check`

### `POST /check`

Checks the status of a given proxy.

**Request Body (JSON):**

```json
{
    "proxy": "<proxy_address>:<port>",
    "type": "<proxy_type>" 
}
```

*   `proxy` (string, required): The proxy address and port (e.g., `123.45.67.89:8080`).
*   `type` (string, required): The proxy type (e.g., `http`, `https`).

**Example Request (using curl):**

```bash
curl -X POST -H "Content-Type: application/json" -d '{"proxy": "13.57.11.118:3128", "type": "http"}' http://127.0.0.1:5000/check
```

**Example Success Response (JSON):**

```json
{
    "status": "alive",
    "latency_ms": 321,
    "country": "United States",
    "proxy_type": "HTTP",
    "anonymous": true
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
