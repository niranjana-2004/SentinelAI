from typing import Generator
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    """Provide a TestClient instance configured for HTTP testing."""
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
