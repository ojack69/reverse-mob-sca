#!/usr/bin/env python3
import argparse
import logging
import os
import plistlib
import sys

logger = logging.getLogger("extract-packages")


def extract_packages(base_path: str):
    packages = set()
    for root, _, files in os.walk(base_path):
        if "Info.plist" not in files:
            continue

        plist_path = os.path.join(root, "Info.plist")
        try:
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)
        except (plistlib.InvalidFileException, OSError) as e:
            logger.warning("Skipping %s: %s", plist_path, e)
            continue

        bundle_name = plist.get("CFBundleName")
        version = plist.get("CFBundleShortVersionString")
        bundle_identifier = plist.get("CFBundleIdentifier", "")

        if bundle_name and version:
            packages.add(f"{bundle_name}@{version}@{bundle_identifier}")

    return sorted(packages)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Walk an extracted iOS .app/.ipa bundle and list embedded "
        "frameworks as name@version@bundle_identifier, read from their Info.plist files. "
        "Works on any OS (uses plistlib, no dependency on macOS's plutil)."
    )
    parser.add_argument(
        "base_path",
        nargs="?",
        default="./",
        help="Path to the extracted app bundle (default: ./)",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if not os.path.isdir(args.base_path):
        logger.error("Not a directory: %s", args.base_path)
        sys.exit(1)

    for line in extract_packages(args.base_path):
        print(line)
