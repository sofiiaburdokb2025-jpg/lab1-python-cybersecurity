import math


class InvalidDataError(ValueError, TypeError):
    """Помилка некоректного типу або структури вхідних даних."""


def extract_record(payload: dict, cve_id: str) -> dict | None:
    """
    Перевіряє відповідь NVD і витягує дані про CVE.
    Повертає None, якщо вразливість не знайдена.
    """
    if not isinstance(payload, dict):
        raise InvalidDataError("NVD response must be a dictionary")

    vulnerabilities = payload.get("vulnerabilities")

    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 1:
        raise ValueError("Invalid vulnerabilities list")

    if not vulnerabilities:
        return None

    item = vulnerabilities[0]
    if not isinstance(item, dict):
        raise InvalidDataError("Vulnerability item must be a dictionary")

    cve = item.get("cve")
    if not isinstance(cve, dict):
        raise InvalidDataError("CVE data must be a dictionary")

    if cve.get("id") != cve_id:
        raise ValueError("CVE ID does not match the requested ID")

    status = cve.get("vulnStatus")
    if "vulnStatus" in cve and (not isinstance(status, str) or not status.strip()):
        raise ValueError("Invalid vulnerability status")

    description = None
    descriptions = cve.get("descriptions", [])

    if not isinstance(descriptions, list):
        raise InvalidDataError("Descriptions must be a list")

    for entry in descriptions:
        if not isinstance(entry, dict):
            raise InvalidDataError("Description item must be a dictionary")

        lang = entry.get("lang")
        value = entry.get("value")

        if not isinstance(lang, str) or not isinstance(value, str):
            raise InvalidDataError("Invalid description fields")

        if lang == "en" and value.strip():
            description = value
            break

    record = {
        "description": description,
        "vuln_status": status,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "observed": None,
    }

    if status is None or status == "Rejected":
        return record

    metrics = cve.get("metrics")

    if metrics is None and "metrics" not in cve:
        return record

    if not isinstance(metrics, dict):
        raise InvalidDataError("Metrics must be a dictionary")

    cvss_metrics = metrics.get("cvssMetricV31")

    if cvss_metrics is None and "cvssMetricV31" not in metrics:
        return record

    if not isinstance(cvss_metrics, list):
        raise InvalidDataError("CVSS v3.1 metrics must be a list")

    if not cvss_metrics:
        return record

    for metric in cvss_metrics:
        if not isinstance(metric, dict):
            raise InvalidDataError("CVSS metric must be a dictionary")

    selected = next(
        (metric for metric in cvss_metrics if metric.get("type") == "Primary"),
        cvss_metrics[0],
    )

    cvss_data = selected.get("cvssData")

    if not isinstance(cvss_data, dict):
        raise InvalidDataError("cvssData must be a dictionary")

    version = cvss_data.get("version")
    if "version" in cvss_data:
        if not isinstance(version, str) or not version.strip():
            raise ValueError("Invalid CVSS version")
        if version != "3.1":
            raise ValueError("Only CVSS version 3.1 is supported")

    vector = cvss_data.get("vectorString")
    if "vectorString" in cvss_data and (
        not isinstance(vector, str) or not vector.strip()
    ):
        raise ValueError("Invalid CVSS vector")

    source = selected.get("source")
    if "source" in selected and (not isinstance(source, str) or not source.strip()):
        raise ValueError("Invalid CVSS source")

    score = cvss_data.get("baseScore")
    if "baseScore" in cvss_data and (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= 10
    ):
        raise ValueError("Invalid CVSS base score")

    privileges = cvss_data.get("privilegesRequired")
    if "privilegesRequired" in cvss_data:
        if not isinstance(privileges, str):
            raise ValueError("Invalid privilegesRequired value")
        if privileges not in {"NONE", "LOW", "HIGH"}:
            raise ValueError("Unsupported privilegesRequired value")

    record.update(
        {
            "cvss_version": version,
            "score": score,
            "score_source": source,
            "vector": vector,
            "observed": privileges,
        }
    )

    return record


def build_report(record: dict | None, cve_id: str, variant: int) -> dict:
    """Формує звіт за правилом аналізу відповідного варіанта."""
    if isinstance(variant, bool) or not isinstance(variant, int):
        raise InvalidDataError("Variant must be an integer")

    if not 1 <= variant <= 15:
        raise ValueError("Variant must be between 1 and 15")

    if variant != 3:
        raise ValueError("This implementation supports variant 3 only")

    rule = {
        "threshold": 7.0,
        "field": "privilegesRequired",
        "expected": "NONE",
    }

    if record is None:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": None,
            "vuln_status": None,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "not_found",
        }

    if not isinstance(record, dict):
        raise InvalidDataError("Record must be a dictionary")

    report = {
        "cve_id": cve_id,
        "variant": variant,
        "description": record["description"],
        "vuln_status": record["vuln_status"],
        "cvss_version": record["cvss_version"],
        "score": record["score"],
        "score_source": record["score_source"],
        "vector": record["vector"],
        "rule": rule,
        "observed": record["observed"],
        "decision": "insufficient_data",
    }

    if record["vuln_status"] == "Rejected":
        report["decision"] = "rejected"
        return report

    if record["vuln_status"] is None:
        return report

    if (
        record["cvss_version"] != "3.1"
        or record["score"] is None
        or record["observed"] is None
    ):
        return report

    if record["score"] >= rule["threshold"] and record["observed"] == rule["expected"]:
        report["decision"] = "review"
    else:
        report["decision"] = "other"

    return report
