import base64
import logging
import sys
import time

import requests

from reverse_mob_sca.net import REQUEST_TIMEOUT
from reverse_mob_sca.severity import get_severity_by_cvss_score
from reverse_mob_sca.validate import component_key

logger = logging.getLogger("mobile-sca")

NAME = "sonatype"
URL = "https://api.guide.sonatype.com/api/v3/component-report"
CHUNK_SIZE = 50
MAX_RATE_LIMIT_RETRIES = 5


def parse_component_name(coordinates: str, platform: str):
    try:
        if platform == "android":
            remainder = coordinates.replace("pkg:maven/", "")
            namespace_and_name, version = remainder.rsplit("@", 1)
            group, package = namespace_and_name.split("/", 1)
            return f"{group}:{package}", version

        remainder = coordinates.replace("pkg:cocoapods/", "")
        name, version = remainder.split("@")[0:2]
        return name, version
    except (ValueError, IndexError) as e:
        raise ValueError(f"malformed coordinates {coordinates!r}: {e}") from e


def _normalize_vuln(v: dict):
    score = v.get("cvssScore")
    cve = v.get("cve") or v["id"]
    return {
        "cve": cve,
        "aliases": sorted({v["id"]} - {cve}),
        "cvssScore": score,
        "severity": get_severity_by_cvss_score(score),
        "references": [r for r in [v.get("reference")] + v.get("externalReferences", []) if r],
    }


def _query_chunk(session, chunk: list, platform: str, auth_header: str):
    headers = {
        "Accept": "application/vnd.ossindex.component-report.v1+json",
        "Content-Type": "application/vnd.ossindex.component-report-request.v1+json",
        "Authorization": auth_header,
    }
    body = {"coordinates": [entry["purl"] for entry in chunk]}

    for attempt in range(1, MAX_RATE_LIMIT_RETRIES + 1):
        try:
            response = session.post(URL, json=body, headers=headers, timeout=REQUEST_TIMEOUT)
        except requests.exceptions.RequestException as e:
            logger.error("Request to Sonatype failed: %s", e)
            return {}

        if response.status_code == 401:
            logger.error("Unauthorized! Check your username or API Key")
            sys.exit(1)

        if response.status_code == 429:
            logger.warning(
                "Rate limit exceeded (attempt %d/%d), waiting 30 seconds before retrying...",
                attempt,
                MAX_RATE_LIMIT_RETRIES,
            )
            time.sleep(30)
            continue

        if response.status_code != 200:
            logger.error(
                "Unexpected response %d from Sonatype: %s",
                response.status_code,
                response.text[:500],
            )
            return {}

        try:
            result = response.json()
        except ValueError as e:
            logger.error("Failed to decode Sonatype JSON response: %s", e)
            return {}

        data = {}
        for item in result:
            try:
                name, version = parse_component_name(item["coordinates"], platform)
                vulns = [_normalize_vuln(v) for v in item.get("vulnerabilities", [])]
            except (KeyError, ValueError) as e:
                logger.warning("Skipping malformed Sonatype response item: %s", e)
                continue

            data[component_key(name, version)] = {
                "description": item.get("description", ""),
                "reference": item.get("reference", ""),
                "vulnerabilities": vulns,
            }

        # Requests are rate limited
        time.sleep(5)
        return data

    logger.error(
        "Exceeded %d retries due to rate limiting, giving up on this chunk",
        MAX_RATE_LIMIT_RETRIES,
    )
    return {}


def query(session, entries: list, platform: str, username: str, api_key: str, data: dict = None):
    """Fill and return {component_key: {description, reference, vulnerabilities}}.

    Results are accumulated into `data` chunk by chunk, so a caller passing its own dict
    keeps partial results if interrupted.
    """
    auth_header = "Basic " + base64.b64encode(f"{username}:{api_key}".encode()).decode()

    data = {} if data is None else data
    chunks = [entries[i : i + CHUNK_SIZE] for i in range(0, len(entries), CHUNK_SIZE)]
    for idx, chunk in enumerate(chunks):
        logger.info("Querying Sonatype for chunk %d/%d (%d components)", idx + 1, len(chunks), len(chunk))
        try:
            data.update(_query_chunk(session, chunk, platform, auth_header))
        except Exception as e:
            logger.error("Unexpected error processing Sonatype chunk %d: %s", idx + 1, e)

    return data
