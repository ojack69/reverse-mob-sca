import logging

import requests

from reverse_mob_sca.net import REQUEST_TIMEOUT
from reverse_mob_sca.severity import (
    get_severity_by_cvss_score,
    score_from_vector,
    severity_from_label,
)
from reverse_mob_sca.validate import component_key

logger = logging.getLogger("mobile-sca")

NAME = "osv"
QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/{}"
BATCH_SIZE = 1000  # OSV querybatch limit
MAX_PAGES = 20

# OSV ecosystems per platform. CocoaPods is not an OSV ecosystem, so iOS isn't supported.
ECOSYSTEMS = {"android": "Maven"}


def _post_batch(session, queries: list):
    response = session.post(QUERYBATCH_URL, json={"queries": queries}, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response.json().get("results", [])


def _vuln_ids(session, entries: list, ecosystem: str):
    """Return {component_key: [vuln ids]} via querybatch, following per-query pagination."""
    ids = {}
    for start in range(0, len(entries), BATCH_SIZE):
        batch = entries[start : start + BATCH_SIZE]
        queries = [
            {"package": {"ecosystem": ecosystem, "name": e["name"]}, "version": e["version"]}
            for e in batch
        ]
        results = _post_batch(session, queries)

        for entry, query, result in zip(batch, queries, results):
            found = [v["id"] for v in result.get("vulns", [])]
            token = result.get("next_page_token")
            pages = 1
            while token and pages < MAX_PAGES:
                page = _post_batch(session, [{**query, "page_token": token}])[0]
                found += [v["id"] for v in page.get("vulns", [])]
                token = page.get("next_page_token")
                pages += 1
            if token:
                logger.warning("OSV results for %s truncated after %d pages", entry["purl"], pages)

            ids[component_key(entry["name"], entry["version"])] = found

    return ids


def _normalize_vuln(osv: dict):
    aliases = osv.get("aliases", [])
    cves = [a for a in aliases if a.startswith("CVE-")]
    cve = cves[0] if cves else osv["id"]

    score = None
    for sev in osv.get("severity", []):
        score = score_from_vector(sev.get("score", ""))
        if score is not None:
            break

    if score is not None:
        severity = get_severity_by_cvss_score(score)
    else:
        severity = severity_from_label(osv.get("database_specific", {}).get("severity"))

    return {
        "cve": cve,
        "aliases": sorted(({osv["id"]} | set(aliases)) - {cve}),
        "cvssScore": score,
        "severity": severity,
        "references": [r["url"] for r in osv.get("references", []) if r.get("url")],
    }


def query(session, entries: list, platform: str):
    """Return {component_key: {vulnerabilities}} for checked components."""
    ecosystem = ECOSYSTEMS[platform]
    logger.info("Querying OSV for %d components", len(entries))

    try:
        ids = _vuln_ids(session, entries, ecosystem)
    except (requests.exceptions.RequestException, ValueError) as e:
        logger.error("OSV querybatch failed: %s", e)
        return {}

    details = {}
    for vuln_id in sorted({i for found in ids.values() for i in found}):
        try:
            response = session.get(VULN_URL.format(vuln_id), timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            details[vuln_id] = _normalize_vuln(response.json())
        except (requests.exceptions.RequestException, ValueError, KeyError) as e:
            logger.warning("Failed to fetch OSV advisory %s: %s", vuln_id, e)

    return {
        key: {"vulnerabilities": [details[i] for i in found if i in details]}
        for key, found in ids.items()
    }
