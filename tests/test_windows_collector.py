"""
Pytest test suite for Week 6: Windows Telemetry Collectors.
Tests login_collector, process_collector, and integration with the agent API.
"""
import sys
import threading
import time
import pytest
import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch
from httpx import AsyncClient, ASGITransport

sys.path.insert(0, str(Path(__file__).parent.parent))

from storage.schema import EventType, EventSource, LifeShieldEvent
from agent.normalizer import normalize_event
from agent.main import app
from collectors.windows.login_collector import (
    _parse_logon_event,
    _build_payload,
    _extract_string_inserts,
    poll_login_events,
    make_login_collector_thread,
)
from collectors.windows.process_collector import (
    _build_start_payload,
    _build_end_payload,
    _safe_proc_info,
    poll_process_events,
    make_process_collector_thread,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    """AsyncClient fixture with app lifespan context."""
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac


class MockWinEvent:
    def __init__(self, event_id: int, record_number: int, string_inserts: list[str]):
        self.EventID = event_id
        self.RecordNumber = record_number
        self.StringInserts = string_inserts


def test_extract_string_inserts():
    ev = MockWinEvent(4624, 100, ["a", "b", "c"])
    assert _extract_string_inserts(ev) == ["a", "b", "c"]

    ev_empty = MockWinEvent(4624, 101, None)
    assert _extract_string_inserts(ev_empty) == []


def test_login_collector_4624_success_payload():
    # Inserts representing Event ID 4624
    # idx 1: subject_user, idx 5: target_user, idx 8: logon_type (2 = Interactive)
    inserts = [""] * 25
    inserts[1] = "SYSTEM"
    inserts[2] = "NT AUTHORITY"
    inserts[5] = "testadmin"
    inserts[6] = "WORKGROUP"
    inserts[7] = "0x12345"
    inserts[8] = "2"
    inserts[11] = "DESKTOP-1"
    inserts[17] = "C:\\Windows\\System32\\winlogon.exe"
    inserts[18] = "192.168.1.50"
    inserts[19] = "54321"

    ev = MockWinEvent(4624, 1001, inserts)
    parsed = _parse_logon_event(ev, 4624)
    assert parsed["target_user"] == "testadmin"
    assert parsed["logon_type"] == "Interactive"
    assert parsed["source_ip"] == "192.168.1.50"

    payload = _build_payload(ev, 4624, EventType.LOGIN_SUCCESS)
    assert payload["event_type"] == "LOGIN_SUCCESS"
    assert payload["source"] == "windows_collector"
    assert payload["user"] == "testadmin"
    assert payload["metadata"]["event_id"] == 4624

    # Verify normalizer validates it cleanly
    normalized = normalize_event(payload)
    assert isinstance(normalized, LifeShieldEvent)
    assert normalized.event_type == EventType.LOGIN_SUCCESS
    assert normalized.source == EventSource.WINDOWS_COLLECTOR


def test_login_collector_4625_failure_payload():
    # Inserts representing Event ID 4625
    inserts = [""] * 25
    inserts[1] = "SYSTEM"
    inserts[5] = "targetuser"
    inserts[8] = "0xC000006A"  # bad password
    inserts[10] = "3"           # Network logon
    inserts[19] = "10.0.0.99"

    ev = MockWinEvent(4625, 1002, inserts)
    parsed = _parse_logon_event(ev, 4625)
    assert parsed["target_user"] == "targetuser"
    assert parsed["failure_reason"] == "0xC000006A"
    assert parsed["logon_type"] == "Network"
    assert parsed["source_ip"] == "10.0.0.99"

    payload = _build_payload(ev, 4625, EventType.LOGIN_FAILURE)
    assert payload["event_type"] == "LOGIN_FAILURE"
    assert payload["source"] == "windows_collector"
    assert payload["user"] == "targetuser"

    normalized = normalize_event(payload)
    assert isinstance(normalized, LifeShieldEvent)
    assert normalized.event_type == EventType.LOGIN_FAILURE
    assert normalized.data["failure_reason"] == "0xC000006A"


def test_process_collector_start_payload():
    proc_info = {
        "pid": 1234,
        "name": "powershell.exe",
        "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "cmdline": "powershell.exe -NoProfile -Command Write-Host Hello",
        "username": "CORP\\analyst",
        "ppid": 5678,
        "create_time": 1700000000.0,
    }

    with patch("collectors.windows.process_collector._parent_name", return_value="explorer.exe"):
        payload = _build_start_payload(proc_info)

    assert payload["event_type"] == "PROCESS_START"
    assert payload["source"] == "windows_collector"
    assert payload["user"] == "CORP\\analyst"
    assert payload["process"] == "powershell.exe"
    assert payload["data"]["pid"] == 1234
    assert payload["data"]["parent_name"] == "explorer.exe"

    normalized = normalize_event(payload)
    assert isinstance(normalized, LifeShieldEvent)
    assert normalized.event_type == EventType.PROCESS_START
    assert normalized.data["cmdline"] == "powershell.exe -NoProfile -Command Write-Host Hello"


def test_process_collector_end_payload():
    proc_info = {
        "pid": 1234,
        "name": "powershell.exe",
        "username": "CORP\\analyst",
        "create_time": 1700000000.0,
    }
    payload = _build_end_payload(1234, proc_info, exit_code=0, now_ts=1700000010.5)

    assert payload["event_type"] == "PROCESS_END"
    assert payload["source"] == "windows_collector"
    assert payload["data"]["pid"] == 1234
    assert payload["data"]["exit_code"] == 0
    assert payload["data"]["runtime_seconds"] == 10.5

    normalized = normalize_event(payload)
    assert isinstance(normalized, LifeShieldEvent)
    assert normalized.event_type == EventType.PROCESS_END


def test_thread_factories():
    stop_event = threading.Event()
    t1 = make_login_collector_thread(stop_event)
    assert isinstance(t1, threading.Thread)
    assert t1.daemon is True
    assert t1.name == "login-collector"

    t2 = make_process_collector_thread(stop_event)
    assert isinstance(t2, threading.Thread)
    assert t2.daemon is True
    assert t2.name == "process-collector"


def test_login_collector_poll_loop_mock():
    stop_event = threading.Event()
    ev1 = MockWinEvent(4624, 201, [""] * 20)
    ev1.StringInserts[5] = "admin_user"
    ev1.StringInserts[8] = "2"

    mock_win32 = MagicMock()
    mock_win32.EVENTLOG_FORWARDS_READ = 1
    mock_win32.EVENTLOG_SEQUENTIAL_READ = 2
    mock_win32.OpenEventLog.return_value = 999
    # Return batch once, then empty batch
    mock_win32.ReadEventLog.side_effect = [[ev1], []]

    posted_urls = []
    posted_payloads = []

    def mock_post(url, json=None, timeout=None):
        posted_urls.append(url)
        posted_payloads.append(json)
        resp = MagicMock()
        resp.status_code = 202
        return resp

    # Stop after one poll
    def set_stop(*args, **kwargs):
        stop_event.set()

    with patch.dict("sys.modules", {"win32evtlog": mock_win32}), \
         patch("requests.post", side_effect=mock_post), \
         patch.object(stop_event, "wait", side_effect=set_stop):
        poll_login_events(stop_event, poll_interval=0.1, agent_url="http://test:8787/events")

    assert len(posted_payloads) == 1
    assert posted_payloads[0]["event_type"] == "LOGIN_SUCCESS"
    assert posted_payloads[0]["user"] == "admin_user"


def test_process_collector_poll_loop_mock():
    stop_event = threading.Event()

    mock_proc1 = MagicMock()
    mock_proc1.pid = 9001
    mock_proc1.name.return_value = "first.exe"
    mock_proc1.exe.return_value = "C:\\first.exe"
    mock_proc1.cmdline.return_value = ["first.exe"]
    mock_proc1.username.return_value = "user1"
    mock_proc1.ppid.return_value = 1
    mock_proc1.create_time.return_value = 1000.0
    mock_proc1.is_running.return_value = True

    mock_proc2 = MagicMock()
    mock_proc2.pid = 9002
    mock_proc2.name.return_value = "second.exe"
    mock_proc2.exe.return_value = "C:\\second.exe"
    mock_proc2.cmdline.return_value = ["second.exe"]
    mock_proc2.username.return_value = "user2"
    mock_proc2.ppid.return_value = 1
    mock_proc2.create_time.return_value = 1010.0
    mock_proc2.is_running.return_value = True

    # Call 1 (seed): [proc1]
    # Call 2 (cycle 1): [proc2] -> proc1 is gone (PROCESS_END), proc2 is new (PROCESS_START)
    cycles = [
        [mock_proc1],
        [mock_proc2],
    ]
    def iter_procs(attrs=None):
        return cycles.pop(0) if cycles else []

    posted_events = []
    def mock_post(url, json=None, timeout=None):
        posted_events.append(json)
        resp = MagicMock()
        resp.status_code = 202
        return resp

    def set_stop(*args, **kwargs):
        stop_event.set()

    with patch("psutil.process_iter", side_effect=iter_procs), \
         patch("requests.post", side_effect=mock_post), \
         patch.object(stop_event, "wait", side_effect=set_stop):
        poll_process_events(stop_event, poll_interval=0.1, agent_url="http://test:8787/events")

    event_types = [p["event_type"] for p in posted_events]
    assert "PROCESS_START" in event_types
    assert "PROCESS_END" in event_types


@pytest.mark.anyio
async def test_api_accepts_windows_collector_events(client: AsyncClient):
    """Integration test: API correctly accepts and saves windows_collector events."""
    events_to_test = [
        {
            "event_type": "LOGIN_SUCCESS",
            "source": "windows_collector",
            "user": "corp_admin",
            "device": "HOST-TEST-01",
            "data": {"logon_type": "Interactive", "source_ip": "127.0.0.1"},
            "metadata": {"collector": "login_collector"},
        },
        {
            "event_type": "PROCESS_START",
            "source": "windows_collector",
            "user": "corp_admin",
            "device": "HOST-TEST-01",
            "process": "cmd.exe",
            "data": {"pid": 4488, "cmdline": "cmd.exe /c dir", "parent_pid": 1100},
            "metadata": {"collector": "process_collector"},
        },
    ]

    for ev in events_to_test:
        resp = await client.post("/events", json=ev)
        assert resp.status_code == 202
        event_id = resp.json()["event_id"]

        await asyncio.sleep(0.3)

        get_resp = await client.get(f"/events/{event_id}")
        assert get_resp.status_code == 200
        saved = get_resp.json()
        assert saved["event_id"] == event_id
        assert saved["event_type"] == ev["event_type"]
        assert saved["source"] == "windows_collector"
        assert saved["user"] == "corp_admin"
