"""
Pytest test suite for Week 8: Behavior Anomaly & File Risk Models.
Tests ml.file_model, ml.behavior_model, and their pipeline integration into the Agent.
"""

import asyncio
import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.main import app
from ml.behavior_model.anomaly import behavior_detector
from ml.file_model.scorer import file_scorer


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    """AsyncClient fixture entering app lifespan context manager."""
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac


# =========================================================================
# File Risk Model Tests
# =========================================================================

def test_file_scorer_benign_document():
    data = {
        "filename": "annual_summary_2026.pdf",
        "path": "C:\\Users\\victim\\Documents\\annual_summary_2026.pdf",
        "size_bytes": 250000,
        "entropy": 4.8,
    }
    result = file_scorer.score(data)
    assert result["risk_score"] <= 0.30
    assert result["severity"] == "LOW"
    assert result["is_threat"] is False


def test_file_scorer_double_extension_masquerading():
    data = {
        "filename": "urgent_invoice.pdf.exe",
        "path": "C:\\Users\\victim\\Downloads\\urgent_invoice.pdf.exe",
        "size_bytes": 18000,
        "entropy": 7.85,
        "is_double_extension": True,
    }
    result = file_scorer.score(data)
    assert result["risk_score"] >= 0.80
    assert result["severity"] in ("HIGH", "CRITICAL")
    assert result["is_threat"] is True
    # Verify indicators explain the triggers
    ind_text = " ".join(result["indicators"])
    assert "Double extension" in ind_text
    assert "entropy" in ind_text


def test_file_scorer_small_dropper_stager():
    data = {
        "filename": "setup_patch.exe",
        "path": "C:\\Users\\victim\\Downloads\\setup_patch.exe",
        "size_bytes": 12000,  # < 30 KB
        "entropy": 6.5,
    }
    result = file_scorer.score(data)
    assert result["risk_score"] >= 0.50
    ind_text = " ".join(result["indicators"])
    assert "stager" in ind_text


def test_file_scorer_script_in_downloads():
    data = {
        "filename": "order_details.vbs",
        "path": "C:\\Users\\victim\\Downloads\\order_details.vbs",
        "size_bytes": 4500,
        "entropy": 5.1,
    }
    result = file_scorer.score(data)
    assert result["risk_score"] >= 0.50
    ind_text = " ".join(result["indicators"])
    assert "script" in ind_text


# =========================================================================
# Behavioral Anomaly Model Tests
# =========================================================================

def test_behavior_detector_normal_daytime_baseline():
    data = {
        "hour_of_day": 14,
        "is_off_hours": 0,
        "is_weekend": 0,
        "event_rate_per_min": 12.0,
        "process_start_rate_per_min": 2.0,
        "failed_login_count": 0,
        "network_conn_rate_per_min": 10.0,
        "dns_query_rate_per_min": 15.0,
        "file_download_rate_per_min": 0.5,
    }
    result = behavior_detector.score(data)
    assert result["anomaly_score"] <= 0.35
    assert result["severity"] in ("LOW", "MEDIUM")
    assert result["is_anomaly"] is False


def test_behavior_detector_failed_login_brute_force():
    data = {
        "hour_of_day": 11,
        "is_off_hours": 0,
        "failed_login_count": 7,
        "event_rate_per_min": 25.0,
    }
    result = behavior_detector.score(data)
    assert result["anomaly_score"] >= 0.80
    assert result["severity"] in ("HIGH", "CRITICAL")
    assert result["is_anomaly"] is True
    ind_text = " ".join(result["indicators"])
    assert "brute force" in ind_text or "failed logins" in ind_text


def test_behavior_detector_process_creation_burst():
    data = {
        "hour_of_day": 15,
        "is_off_hours": 0,
        "process_start_rate_per_min": 55.0,  # burst of 55 proc/min
        "event_rate_per_min": 60.0,
    }
    result = behavior_detector.score(data)
    assert result["anomaly_score"] >= 0.80
    assert result["is_anomaly"] is True
    ind_text = " ".join(result["indicators"])
    assert "process creation" in ind_text.lower()


def test_behavior_detector_off_hours_activity_surge():
    data = {
        "hour_of_day": 3,
        "is_off_hours": 1,
        "event_rate_per_min": 45.0,
        "failed_login_count": 2,
    }
    result = behavior_detector.score(data)
    assert result["anomaly_score"] >= 0.65
    assert result["is_anomaly"] is True
    ind_text = " ".join(result["indicators"])
    assert "off-hours" in ind_text


# =========================================================================
# Agent API Direct Endpoints & Background Pipeline Tests
# =========================================================================

@pytest.mark.anyio
async def test_direct_file_score_endpoint(client: AsyncClient):
    payload = {
        "filename": "remittance_advice.pdf.scr",
        "size_bytes": 14000,
        "entropy": 7.9,
        "is_double_extension": True,
    }
    resp = await client.post("/ml/file/score", json=payload)
    assert resp.status_code == 200
    res = resp.json()
    assert "risk_score" in res
    assert res["risk_score"] >= 0.70
    assert res["is_threat"] is True


@pytest.mark.anyio
async def test_direct_behavior_score_endpoint(client: AsyncClient):
    payload = {
        "hour_of_day": 2,
        "is_off_hours": 1,
        "failed_login_count": 8,
    }
    resp = await client.post("/ml/behavior/score", json=payload)
    assert resp.status_code == 200
    res = resp.json()
    assert "anomaly_score" in res
    assert res["anomaly_score"] >= 0.80
    assert res["is_anomaly"] is True


@pytest.mark.anyio
async def test_background_pipeline_file_threat_detection(client: AsyncClient):
    """Verify that posting a malicious FILE_DOWNLOAD triggers a detection in storage."""
    event_payload = {
        "event_type": "FILE_DOWNLOAD",
        "source": "file_collector",
        "user": "test_victim",
        "device": "WIN-TEST-01",
        "data": {
            "filename": "urgent_bank_payment.pdf.exe",
            "path": "C:\\Users\\victim\\Downloads\\urgent_bank_payment.pdf.exe",
            "size_bytes": 16000,
            "entropy": 7.88,
            "is_double_extension": True,
        },
        "metadata": {"collector": "file_watcher"},
    }

    post_resp = await client.post("/events", json=event_payload)
    assert post_resp.status_code == 202
    event_id = post_resp.json()["event_id"]

    await asyncio.sleep(0.4)

    # Check that detection was saved
    det_resp = await client.get(f"/detections/{event_id}")
    assert det_resp.status_code == 200
    detections = det_resp.json()
    assert len(detections) >= 1
    file_det = [d for d in detections if d["model_name"] == "file_risk_heuristic"][0]
    assert file_det["is_threat"] is True
    assert file_det["risk_score"] >= 0.70


@pytest.mark.anyio
async def test_background_pipeline_login_failure_anomaly_detection(client: AsyncClient):
    """Verify that posting a brute-force LOGIN_FAILURE triggers an anomaly detection."""
    event_payload = {
        "event_type": "LOGIN_FAILURE",
        "source": "windows_collector",
        "user": "administrator",
        "device": "WIN-TEST-01",
        "data": {
            "failed_attempts": 6,
            "source_ip": "198.51.100.44",
            "workstation": "ATTACKER-BOX",
        },
        "metadata": {"collector": "login_collector"},
    }

    post_resp = await client.post("/events", json=event_payload)
    assert post_resp.status_code == 202
    event_id = post_resp.json()["event_id"]

    await asyncio.sleep(0.4)

    det_resp = await client.get(f"/detections/{event_id}")
    assert det_resp.status_code == 200
    detections = det_resp.json()
    assert len(detections) >= 1
    behav_det = [d for d in detections if d["model_name"] == "behavior_isolation_forest"][0]
    assert behav_det["is_threat"] is True
    assert behav_det["risk_score"] >= 0.80
