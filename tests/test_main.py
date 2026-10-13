from fastapi.testclient import TestClient


def test_root_endpoint(client: TestClient) -> None:
    """Validate GET / returns HTTP 200 with expected project payload."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {
        "project": "SentinelAI",
        "message": "SentinelAI backend is running!",
        "version": "0.1.0",
    }


def test_root_health_endpoint(client: TestClient) -> None:
    """Validate GET /health returns HTTP 200 with healthy service payload."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "sentinelai-backend",
    }


def test_api_v1_health_endpoint(client: TestClient) -> None:
    """Validate GET /api/v1/health returns HTTP 200 and matches health schema."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "sentinelai-backend",
    }


def test_docs_endpoint(client: TestClient) -> None:
    """Validate Swagger UI docs endpoint is accessible."""
    response = client.get("/docs")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_openapi_spec_endpoint(client: TestClient) -> None:
    """Validate OpenAPI JSON specification is generated correctly."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    spec = response.json()
    assert spec["info"]["title"] == "SentinelAI"
    assert spec["info"]["version"] == "0.1.0"
    assert "/health" in spec["paths"]
    assert "/api/v1/health" in spec["paths"]


def test_unknown_route_returns_404(client: TestClient) -> None:
    """Validate request to non-existent route returns HTTP 404 with standard error body."""
    response = client.get("/api/v1/unknown-endpoint")
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data


def test_cors_headers_on_allowed_origin(client: TestClient) -> None:
    """Validate CORS headers are attached for explicitly allowed origins."""
    headers = {
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "GET",
    }
    response = client.get("/health", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_unhandled_exception_does_not_leak_details(client: TestClient) -> None:
    """Validate that unhandled server exceptions return 500 without leaking stack traces."""
    @client.app.get("/_test/trigger-error")
    def trigger_error() -> None:
        raise RuntimeError("Sensitive stack trace info")

    response = client.get("/_test/trigger-error")
    assert response.status_code == 500
    data = response.json()
    assert data == {"detail": "Internal server error"}
    assert "Sensitive stack trace info" not in response.text
