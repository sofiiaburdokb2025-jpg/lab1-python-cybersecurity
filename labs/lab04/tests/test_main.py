import json

import pytest

from labs.lab04 import main as main_module

CVE_ID = "CVE-2099-10001"


def make_payload():
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": CVE_ID,
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Synthetic test vulnerability.",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "source": "nvd@nist.gov",
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 9.8,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "privilegesRequired": "NONE",
                                },
                            }
                        ]
                    },
                }
            }
        ]
    }


def test_local_input_does_not_call_api(tmp_path, monkeypatch, capsys):
    input_file = tmp_path / "sample.json"
    input_file.write_text(
        json.dumps(make_payload()),
        encoding="utf-8",
    )

    def forbidden_request(cve_id):
        raise AssertionError("API must not be called")

    monkeypatch.setattr(
        main_module.api_client,
        "fetch_response",
        forbidden_request,
    )

    result = main_module.main(["--cve", CVE_ID, "--input", str(input_file)])

    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert result == 0
    assert report["decision"] == "review"
    assert captured.err == ""


def test_invalid_cve_returns_error(capsys):
    with pytest.raises(SystemExit) as error:
        main_module.main(["--cve", "INVALID-CVE"])

    assert error.value.code == 2
    assert "Неправильний формат CVE" in capsys.readouterr().err


def test_missing_input_file_returns_error(capsys):
    result = main_module.main(
        [
            "--cve",
            CVE_ID,
            "--input",
            "missing_file.json",
        ]
    )

    captured = capsys.readouterr()

    assert result == 1
    assert captured.out == ""
    assert "Помилка читання локального файла" in captured.err


def test_invalid_json_returns_error(tmp_path, capsys):
    input_file = tmp_path / "invalid.json"
    input_file.write_text("{invalid json", encoding="utf-8")

    result = main_module.main(["--cve", CVE_ID, "--input", str(input_file)])

    captured = capsys.readouterr()

    assert result == 1
    assert captured.out == ""
    assert "Помилка" in captured.err


def test_invalid_variant_returns_error(tmp_path, monkeypatch, capsys):
    input_file = tmp_path / "sample.json"
    input_file.write_text(
        json.dumps(make_payload()),
        encoding="utf-8",
    )

    monkeypatch.setattr(main_module, "VARIANT_NUMBER", True)

    result = main_module.main(["--cve", CVE_ID, "--input", str(input_file)])

    captured = capsys.readouterr()

    assert result == 2
    assert captured.out == ""
    assert "номер варіанта" in captured.err
