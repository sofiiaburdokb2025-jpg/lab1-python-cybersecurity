import pytest

from labs.lab04.analysis import build_report, extract_record

CVE_ID = "CVE-2099-10001"


def make_payload(score=7.0, privileges="NONE", status="Analyzed"):
    """Створює тестову відповідь NVD."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": CVE_ID,
                    "vulnStatus": status,
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Test vulnerability",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "source": "test@example.com",
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": score,
                                    "vectorString": "CVSS:3.1/AV:N",
                                    "privilegesRequired": privileges,
                                },
                            }
                        ]
                    },
                }
            }
        ]
    }


def analyze(payload):
    """Витягує запис і формує звіт для варіанта 3."""
    record = extract_record(payload, CVE_ID)
    return build_report(record, CVE_ID, 3)


@pytest.mark.parametrize(
    "score, privileges, expected",
    [
        (6.9, "NONE", "other"),
        (7.0, "NONE", "review"),
        (7.1, "NONE", "review"),
        (9.8, "LOW", "other"),
    ],
)
def test_variant_3_rule(score, privileges, expected):
    report = analyze(make_payload(score, privileges))
    assert report["decision"] == expected


def test_record_not_found():
    payload = {"vulnerabilities": []}

    report = analyze(payload)

    assert report["decision"] == "not_found"
    assert report["score"] is None


def test_rejected_record():
    report = analyze(make_payload(9.8, "NONE", "Rejected"))

    assert report["decision"] == "rejected"


def test_missing_score():
    payload = make_payload()
    cvss_data = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]
    del cvss_data["baseScore"]

    report = analyze(payload)

    assert report["decision"] == "insufficient_data"


def test_missing_privileges():
    payload = make_payload()
    cvss_data = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]
    del cvss_data["privilegesRequired"]

    report = analyze(payload)

    assert report["decision"] == "insufficient_data"


@pytest.mark.parametrize("score", [True, -1, 10.1, float("nan")])
def test_invalid_score(score):
    payload = make_payload(score)

    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


def test_invalid_privileges():
    payload = make_payload(privileges="INVALID")

    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


def test_primary_metric_has_priority():
    payload = make_payload(score=9.8, privileges="NONE")
    metrics = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"]

    metrics.insert(
        0,
        {
            "type": "Secondary",
            "cvssData": {
                "version": "3.1",
                "baseScore": 9.8,
                "privilegesRequired": "LOW",
            },
        },
    )

    record = extract_record(payload, CVE_ID)

    assert record["observed"] == "NONE"


def test_first_metric_is_used_without_primary():
    payload = make_payload(score=8.0, privileges="LOW")
    metrics = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"]

    metrics[0]["type"] = "Secondary"
    metrics.append(
        {
            "type": "Secondary",
            "cvssData": {
                "version": "3.1",
                "baseScore": 9.8,
                "privilegesRequired": "NONE",
            },
        }
    )

    record = extract_record(payload, CVE_ID)

    assert record["observed"] == "LOW"
