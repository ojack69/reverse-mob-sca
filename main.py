import json
import logging
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import argparse
import base64
import os
import random
import string

logger = logging.getLogger("mobile-sca")

REQUEST_TIMEOUT = 30
MAX_RATE_LIMIT_RETRIES = 5


def get_severity_by_cvss_score(score: float):
    if 0.0 <= score < 0.1:
        return "Informational"
    if 0.1 <= score <= 3.9:
        return "Low"
    if 4.0 <= score <= 6.9:
        return "Medium"
    if 7.0 <= score <= 8.9:
        return "High"
    if 9.0 <= score <= 10:
        return "Critical"

    return "Unknown"


def build_coordinate(line: str, platform: str) -> str:
    try:
        if platform == "android":
            group, rest = line.split(":", 1)
            package, version = rest.split("@", 1)
            if not group or not package or not version:
                raise ValueError("empty group/package/version")
            return f"pkg:maven/{group}/{package}@{version}"

        name, version = line.split("@")[0:2]
        if not name or not version:
            raise ValueError("empty name/version")
        return f"pkg:cocoapods/{name}@{version}"
    except (ValueError, IndexError) as e:
        raise ValueError(f"malformed {platform} line {line!r}: {e}") from e


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


def parse(chunk: list, platform: str, username: str, api_key: str, proxy: str = None):
    coordinates = []
    lines = []
    for line in chunk:
        try:
            coordinates.append(build_coordinate(line, platform))
            lines.append(line)
        except ValueError as e:
            logger.warning("Skipping component: %s", e)

    if not coordinates:
        logger.warning("No valid components in this chunk, skipping")
        return []

    basic_auth = base64.b64encode(f"{username}:{api_key}".encode()).decode(
        "utf-8"
    )
    headers = {
        "User-Agent": f"python-{''.join(random.choices(string.ascii_letters + string.digits, k=8))}",
        "Accept": "application/vnd.ossindex.component-report.v1+json",
        "Content-Type": "application/vnd.ossindex.component-report-request.v1+json",
        "Authorization": f"Basic {basic_auth}",
    }

    body = {"coordinates": coordinates}
    url = "https://api.guide.sonatype.com/api/v3/component-report"

    for attempt in range(1, MAX_RATE_LIMIT_RETRIES + 1):
        try:
            response = requests.post(
                url,
                json=body,
                headers=headers,
                proxies={"http": proxy, "https": proxy} if proxy else None,
                verify=not proxy,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as e:
            logger.error("Request to Sonatype failed: %s", e)
            return []

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
            return []

        try:
            result = response.json()
        except ValueError as e:
            logger.error("Failed to decode Sonatype JSON response: %s", e)
            return []

        data = []
        for idx, item in enumerate(result):
            try:
                name, version = parse_component_name(item["coordinates"], platform)
            except (KeyError, ValueError) as e:
                logger.warning("Skipping malformed response item: %s", e)
                continue

            data.append(
                {
                    "platform": platform,
                    "name": name,
                    "version": version,
                    "bundle_identifier": lines[idx].split("@")[-1]
                    if platform == "ios"
                    else None,
                    "description": item.get("description", ""),
                    "reference": item.get("reference", ""),
                    "vulnerabilities": [
                        {
                            "cve": v["id"],
                            "cvssScore": v["cvssScore"],
                            "severity": get_severity_by_cvss_score(v["cvssScore"]),
                            "references": [v["reference"]] + v["externalReferences"],
                        }
                        for v in item.get("vulnerabilities", [])
                    ],
                }
            )

        # Requests are rate limited
        time.sleep(5)
        return data

    logger.error(
        "Exceeded %d retries due to rate limiting, giving up on this chunk",
        MAX_RATE_LIMIT_RETRIES,
    )
    return []


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f",
        "--file",
        dest="packages_list",
        required=True,
        type=str,
        help="For --platform ios, use output from extract_packages_from_ipa.py. "
        "For --platform android, use output from extract_packages_from_apk.py, or a flat file of "
        "group:artifact@version lines from MobSF SBOM analysis.",
    )
    parser.add_argument("-o", "--output", dest="output", required=True, type=str)
    parser.add_argument(
        "-p",
        "--platform",
        dest="platform",
        required=True,
        choices=["android", "ios"],
        type=str,
    )
    parser.add_argument("--username", dest="username", required=True, type=str)
    parser.add_argument("--api-key", dest="api_key", required=True, type=str)
    parser.add_argument(
        "--proxy",
        dest="proxy",
        required=False,
        type=str,
        default=None,
        help="Proxy URL (e.g. http://localhost:8080) to route requests through, for interception/debugging. "
        "Disables TLS certificate verification when set.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    packages_list = args.packages_list
    output = args.output
    platform = args.platform
    username = args.username
    api_key = args.api_key
    proxy = args.proxy

    if not os.path.exists(packages_list):
        logger.error("File does not exist: %s", packages_list)
        sys.exit(1)

    try:
        with open(packages_list, "r") as f:
            libs = [line.strip() for line in f if line.strip()]
    except OSError as e:
        logger.error("Failed to read %s: %s", packages_list, e)
        sys.exit(1)

    if not libs:
        logger.error("No components found in %s", packages_list)
        sys.exit(1)

    logger.info("Loaded %d components from %s (platform=%s)", len(libs), packages_list, platform)

    data = []
    chunk_size = 50
    chunks = [libs[i : i + chunk_size] for i in range(0, len(libs), chunk_size)]
    for idx, chunk in enumerate(chunks):
        logger.info("Querying Sonatype for chunk %d/%d (%d components)", idx + 1, len(chunks), len(chunk))
        try:
            data += parse(chunk, platform, username, api_key, proxy)
        except KeyboardInterrupt:
            logger.warning("Interrupted by user, writing partial results to %s", output)
            break
        except Exception as e:
            logger.error("Unexpected error processing chunk %d: %s", idx + 1, e)
            continue

    try:
        with open(output, "w") as f:
            json.dump(data, f, indent=4)
    except OSError as e:
        logger.error("Failed to write output to %s: %s", output, e)
        sys.exit(1)

    logger.info("Wrote %d results to %s", len(data), output)
