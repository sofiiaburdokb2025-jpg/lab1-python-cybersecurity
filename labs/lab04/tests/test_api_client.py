import pytest
import requests

from labs.lab04 import api_client

CVE_ID = "CVE-2099-10001"


def test_build_headers_without_api_key(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    headers = api_client.build_headers()

    assert headers == {"Accept": "application/json"}


def test_build_headers_with_api_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-api-key")

    headers = api_client.build_headers()

    assert headers["Accept"] == "application/json"
    assert headers["apiKey"] == "test-api-key"


def test_fetch_response_success(monkeypatch):
    expected_payload = {"vulnerabilities": []}
    captured = {}

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return expected_payload

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return FakeResponse()

    monkeypatch.setattr(api_client.requests, "get", fake_get)

    result = api_client.fetch_response(CVE_ID)

    assert result == expected_payload
    assert captured["params"] == {"cveId": CVE_ID}
    assert captured["timeout"] == (3.05, 10)
    assert captured["allow_redirects"] is False
    assert captured["headers"]["Accept"] == "application/json"


def test_fetch_response_http_error(monkeypatch):
    class FakeResponse:
        status_code = 404

        def raise_for_status(self):
            raise requests.HTTPError("Not Found")

    monkeypatch.setattr(
        api_client.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(),
    )

    with pytest.raises(requests.HTTPError):
        api_client.fetch_response(CVE_ID)


def test_fetch_response_network_error(monkeypatch):
    def fake_get(*args, **kwargs):
        raise requests.ConnectionError("Connection failed")

    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(requests.ConnectionError):
        api_client.fetch_response(CVE_ID)
