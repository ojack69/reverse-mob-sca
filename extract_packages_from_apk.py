#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import zipfile

logger = logging.getLogger("extract-packages-apk")


def _parse_properties(data: bytes):
    properties = {}
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        key, sep, value = line.partition("=")
        if not sep:
            continue

        properties[key.strip()] = value.strip()

    return properties


def _from_pom_properties(data: bytes, source: str):
    properties = _parse_properties(data)
    group_id = properties.get("groupId")
    artifact_id = properties.get("artifactId")
    version = properties.get("version")

    if not (group_id and artifact_id and version):
        logger.warning("Skipping %s: missing groupId/artifactId/version", source)
        return None

    return group_id, artifact_id, version


def _from_dependency_version_file(data: bytes, source: str):
    # AGP writes one META-INF/<groupId>_<artifactId>.version file per third-party
    # dependency (used by Play Console's SDK index); the file's content is the bare
    # version string. This is the dominant marker in modern (AGP-built) release APKs
    # -- pom.properties is comparatively rare there.
    filename = os.path.basename(source)
    stem = filename[: -len(".version")]
    group_id, sep, artifact_id = stem.partition("_")
    version = data.decode("utf-8", errors="replace").strip()

    if not (sep and group_id and artifact_id and version):
        logger.warning("Skipping %s: could not parse group/artifact/version", source)
        return None

    return group_id, artifact_id, version


def _classify(rel_path: str):
    parts = rel_path.replace("\\", "/").split("/")

    if parts[-1] == "pom.properties" and "META-INF" in parts and "maven" in parts:
        return _from_pom_properties

    if len(parts) == 2 and parts[0] == "META-INF" and parts[1].endswith(".version"):
        return _from_dependency_version_file

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
            parser = _classify(name)
            if parser is None:
                continue

            try:
                data = zf.read(name)
            except (KeyError, zipfile.BadZipFile, OSError) as e:
                logger.warning("Skipping %s: %s", name, e)
                continue

            component = parser(data, name)
            if component:
                packages.add("{}:{}@{}".format(*component))

    return packages


def _extract_from_directory(base_path: str):
    packages = set()
    for root, _, files in os.walk(base_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, base_path)

            parser = _classify(rel_path)
            if parser is None:
                continue

            try:
                with open(file_path, "rb") as f:
                    data = f.read()
            except OSError as e:
                logger.warning("Skipping %s: %s", file_path, e)
                continue

            component = parser(data, rel_path)
            if component:
                packages.add("{}:{}@{}".format(*component))

    return packages


def extract_packages(base_path: str):
    if os.path.isdir(base_path):
        packages = _extract_from_directory(base_path)
    else:
        packages = _extract_from_archive(base_path)

    return sorted(packages)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="List third-party Maven/Gradle dependencies of an Android app as "
        "group:artifact@version, read from metadata embedded in the APK by the build "
        "system: META-INF/<group>_<artifact>.version files (AGP's dependency metadata, "
        "the dominant marker in modern release APKs) and META-INF/maven/*/*/pom.properties "
        "files (older Maven/Gradle publishing convention). Accepts either a raw .apk file "
        "or an already-extracted APK directory. Best-effort: only dependencies that embed "
        "one of these markers are found (some builds strip or exclude META-INF entries, or "
        "disable dependency metadata via android.dependenciesInfo)."
    )
    parser.add_argument(
        "base_path",
        nargs="?",
        default="./",
        help="Path to an .apk file or an extracted APK directory (default: ./)",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if not os.path.exists(args.base_path):
        logger.error("Path does not exist: %s", args.base_path)
        sys.exit(1)

    for line in extract_packages(args.base_path):
        print(line)
