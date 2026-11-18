import pytest


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Забороняє мережеві запити та прибирає успадкований API-ключ."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")
