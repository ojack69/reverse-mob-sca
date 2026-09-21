import requests
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

import json
import re
import sys
import argparse
import os
import time
import warnings

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.3 Safari/605.1.15"
}


def get_latest_version(parent_url):
    r = requests.get(parent_url, headers=HEADERS, proxies={"http": "http://localhost:8080", "https": "http://localhost:8080"}, verify=False)
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "html.parser")

    # Version table
    version_table = soup.select("table.versions tr")

    for row in version_table:
        link = row.select_one("a.vbtn:not(.alpha):not(.beta)") # do not include alpha or beta versions
        if link:
            version = link.text.strip()
            if re.match(r"\d+(\.\d+)*", version):
                return version

    return None


def get_cves(response_text: str):
    soup = BeautifulSoup(response_text, "html.parser")
    text = soup.get_text(" ")
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d+", text)))
    return cves


def get_home(response_text: str):
    soup = BeautifulSoup(response_text, "html.parser")
    return soup.select_one('a.inspected-url-link')['href']


def parse_artifact(url):

    parts = url.strip("/").split("/")
    version = parts[-1]

    parent_url = "/".join(parts[:-1])

    latest_version = get_latest_version(parent_url)

    parent_cves = get_cves(f"{parent_url}/{latest_version}")

    r = requests.get(url, headers=HEADERS)
    r.raise_for_status()
    cves = get_cves(r.text)
    home = get_home(r.text)

    result = {
        "library": f"{parts[-3]}:{parts[-2]}",
        "current_version": version,
        "latest_version": latest_version,
        "cves": cves,
        "parent_cves": parent_cves,
        "maven": url,
        "home": home
    }
    time.sleep(0.3)

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', dest='packages_list', required=True, type=str, help='Use output from MobSF')
    parser.add_argument('-o', '--output', dest='output', required=True, type=str)
    args = parser.parse_args()
    
    packages_list = args.packages_list
    output = args.output
    
    if not os.path.exists(packages_list):
        print(f"File does not exist: {packages_list}")
        exit(1)

    data = []
    libs = []
    with open(packages_list, "r") as f:
        libs = f.readlines()
    libs = list(map(lambda x: x.strip(), libs))

    for idx, lib in enumerate(libs):
        group = lib.split(":")[0]
        package = lib.split(":")[1].split("@")[0]
        version = lib.split(":")[1].split("@")[1]
        url = f"https://mvnrepository.com/artifact/{group}/{package}/{version}"
        print(f"[+] Url: {url}")
        try:
            data.append(parse_artifact(url))
        except KeyboardInterrupt:
            exit(1)
        except BaseException as e:
            print(f"[Warning] Error at line {idx + 1} - {e}")
            continue

    with open(output, "w") as f:
        json.dump(data, f, indent=4)
