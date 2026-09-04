"""
Pytest test suite for LifeShield Agent API.
"""
import sys
import pytest
import asyncio
from pathlib import Path
from httpx import AsyncClient, ASGITransport

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.main import app


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
async def client():
    """
    AsyncClient fixture entering app lifespan context manager so background queue worker runs.
    """
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac


@pytest.mark.anyio
async def test_health_check(client: AsyncClient):
    """Tests /health endpoint returns HTTP 200 and expected keys."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "queue_size" in data
    assert "stored_events" in data


@pytest.mark.anyio
async def test_post_event_and_retrieve(client: AsyncClient):
    """Tests posting a valid event and confirming it is processed into storage."""
    payload = {
        "event_type": "LOGIN_FAILURE",
        "source": "manual",
        "user": "pytest_user",
        "device": "pytest_device",
        "data": {"ip": "192.168.1.100", "attempts": 3},
    }

    post_resp = await client.post("/events", json=payload)
    assert post_resp.status_code == 202
    post_data = post_resp.json()
    assert post_data["status"] == "queued"
    event_id = post_data["event_id"]

    # Yield to let background queue worker process the enqueued event
    await asyncio.sleep(0.3)

    get_resp = await client.get(f"/events/{event_id}")
    assert get_resp.status_code == 200
    event_data = get_resp.json()
    assert event_data["event_id"] == event_id
    assert event_data["event_type"] == "LOGIN_FAILURE"
    assert event_data["user"] == "pytest_user"


@pytest.mark.anyio
async def test_post_invalid_event(client: AsyncClient):
    """Tests posting an invalid event payload returns HTTP 400."""
    invalid_payload = {
        "event_type": "INVALID_EVENT_TYPE",
        "source": "unknown_source",
    }
    response = await client.post("/events", json=invalid_payload)
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data


@pytest.mark.anyio
async def test_list_events(client: AsyncClient):
    """Tests /events endpoint returns a list of events."""
    response = await client.get("/events?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


@pytest.mark.anyio
async def test_stats_endpoint(client: AsyncClient):
    """Tests /stats endpoint returns database metrics."""
    response = await client.get("/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "by_type" in data
    assert "by_source" in data
