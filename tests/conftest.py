"""
Pytest hooks and phase documentation.

Before treating a phase as complete, run the full suite from the project root:

  python -m pytest tests/ -v

Targeted smoke by area:

  Phase 0 — Dashboard (no auth):  pytest tests/test_honeypot.py::TestDashboard -v
  Phase 1 — Logger + Discord + env: pytest tests/test_logger.py tests/test_honeypot.py::TestLogger tests/test_honeypot.py::TestDiscordAlerts tests/test_config_env.py -v
  Phase 2 — GeoIP:                 pytest tests/test_geoip.py -v
  Phase 3 — SSE attack stream:     pytest tests/test_attack_map.py -v
"""

import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "phase0: dashboard contract (no auth)")
    config.addinivalue_line("markers", "phase1: foundation — DB, JSONL, callbacks, Discord, config")
    config.addinivalue_line("markers", "phase2: GeoIP enrichment")
    config.addinivalue_line("markers", "phase3: live SSE / attack stream")


def pytest_collection_modifyitems(config, items):
    """Attach phase markers from file/class names for optional filtering."""
    for item in items:
        nodeid = item.nodeid
        if "TestDashboard" in nodeid and "test_honeypot" in nodeid:
            item.add_marker(pytest.mark.phase0)
        if (
            "test_logger.py" in nodeid
            or "test_config_env.py" in nodeid
            or "TestDiscordAlerts" in nodeid
            or ("::TestLogger::" in nodeid and "test_honeypot.py" in nodeid)
        ):
            item.add_marker(pytest.mark.phase1)
        if "test_geoip.py" in nodeid:
            item.add_marker(pytest.mark.phase2)
        if "test_attack_map.py" in nodeid:
            item.add_marker(pytest.mark.phase3)
