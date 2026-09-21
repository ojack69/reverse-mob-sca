#!/usr/bin/env python3
import argparse
import logging
import os
import plistlib
import sys
import zipfile

logger = logging.getLogger("extract-packages")


def _parse_plist(data: bytes):
    try:
        return plistlib.loads(data)
    except plistlib.InvalidFileException:
        return None


def _extract_from_archive(archive_path: str):
    packages = set()
    try:
        zf = zipfile.ZipFile(archive_path)
    except (zipfile.BadZipFile, OSError) as e:
        logger.error("Failed to open %s: %s", archive_path, e)
        sys.exit(1)

    with zf:
        for name in zf.namelist():
            if not name.endswith("Info.plist"):
                continue

            try:
                data = zf.read(name)
            except (KeyError, zipfile.BadZipFile, OSError) as e:
                logger.warning("Skipping %s: %s", name, e)
                continue

            plist = _parse_plist(data)
            if plist is None:
                logger.warning("Skipping %s: invalid plist", name)
                continue

            _add_package(packages, plist)

    return packages


def _extract_from_directory(base_path: str):
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

        _add_package(packages, plist)

    return packages


def _add_package(packages: set, plist: dict):
    bundle_name = plist.get("CFBundleName")
    version = plist.get("CFBundleShortVersionString")
    bundle_identifier = plist.get("CFBundleIdentifier", "")

    if bundle_name and version:
        packages.add(f"{bundle_name}@{version}@{bundle_identifier}")


def extract_packages(base_path: str):
    if os.path.isdir(base_path):
        packages = _extract_from_directory(base_path)
    else:
        packages = _extract_from_archive(base_path)

    return sorted(packages)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="List embedded frameworks of an iOS app as name@version@bundle_identifier, "
        "read from their Info.plist files. Accepts either a raw .ipa file or an already-extracted "
        ".app/.ipa bundle directory. Works on any OS (uses plistlib/zipfile, no dependency on "
        "macOS's plutil)."
    )
    parser.add_argument(
        "base_path",
        nargs="?",
        default="./",
        help="Path to a .ipa file or an extracted app bundle directory (default: ./)",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if not os.path.exists(args.base_path):
        logger.error("Path does not exist: %s", args.base_path)
        sys.exit(1)

    for line in extract_packages(args.base_path):
        print(line)
