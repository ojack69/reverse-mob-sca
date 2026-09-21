import json
import re
import sys
import time

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import argparse
import random
import string
import os
import base64


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


def parse(chunk: list, username: str, api_key: str):
    basic_auth = base64.b64encode(f"{username}:{api_key}".encode("utf-8")).decode(
        "utf-8"
    )
    headers = {
        "User-Agent": f"python-{''.join(random.choices(string.ascii_letters + string.digits, k=8))}",
        "Accept": "application/vnd.ossindex.component-report.v1+json",
        "Content-Type": "application/vnd.ossindex.component-report-request.v1+json",
        "Authorization": f"Basic {basic_auth}",
    }

    body = {
        "coordinates": list(
            map(lambda x: f"pkg:cocoapods/{'@'.join(x.split('@')[0:2])}", chunk)
        )
    }
    # url = "https://ossindex.sonatype.org/api/v3/authorized/component-report"
    url = "https://api.guide.sonatype.com/api/v3/component-report"
    response = requests.post(
        url,
        json=body,
        headers=headers,
        # proxies={"http": "http://localhost:8080", "https": "http://localhost:8080"},
        verify=False,
    )
    if response.status_code == 401:
        print("Unauthorized! Check your username or API Key")
        exit(1)

    if response.status_code == 429:
        print("Rate limited exceeded, wating 30 seconds before retrying...")
        time.sleep(30)
        return parse(url, username, api_key)

    data = []
    if response.status_code == 200:
        result = response.json()
        for idx, item in enumerate(result):
            name = item["coordinates"].replace("pkg:cocoapods/", "")
            data.append(
                {
                    "name": name.split("@")[0],
                    "version": name.split("@")[1],
                    "bundle_identifier": chunk[idx].split('@')[-1],
                    "description": item["description"]
                    if "description" in item.keys()
                    else "",
                    "reference": item["reference"]
                    if "reference" in item.keys()
                    else "",
                    "vulnerabilities": list(
                        map(
                            lambda x: {
                                "cve": x["id"],
                                "cvssScore": x["cvssScore"],
                                "severity": get_severity_by_cvss_score(x["cvssScore"]),
                                "references": [x["reference"]]
                                + x["externalReferences"],
                            },
                            item["vulnerabilities"]
                            if "vulnerabilities" in item.keys()
                            else [],
                        )
                    ),
                }
            )

    # Requests are rate limited
    time.sleep(5)
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f",
        "--file",
        dest="packages_list",
        required=True,
        type=str,
        help="Use output from extract_packages_from_app_bundle",
    )
    parser.add_argument("-o", "--output", dest="output", required=True, type=str)
    parser.add_argument("--username", dest="username", required=True, type=str)
    parser.add_argument("--api-key", dest="api_key", required=True, type=str)
    args = parser.parse_args()

    packages_list = args.packages_list
    output = args.output
    username = args.username
    api_key = args.api_key

    if not os.path.exists(packages_list):
        print(f"File does not exist: {packages_list}")
        exit(1)

    data = []
    libs = []
    with open(packages_list, "r") as f:
        libs = f.readlines()
    libs = list(map(lambda x: x.strip(), libs))

    chunk_size = 50
    chunks = [libs[i : i + chunk_size] for i in range(0, len(libs), chunk_size)]
    for idx, chunk in enumerate(chunks):
        # try:
        data = data + parse(chunk, username, api_key)
        # except BaseException as e:
        #     print(f"[Warning] Error with chunk {idx + 1} - {e}")
        #     continue

    with open(output, "w") as f:
        json.dump(data, f, indent=4)
