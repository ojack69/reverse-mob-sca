import logging
import os
import plistlib
import zipfile

logger = logging.getLogger("mobile-sca")


# ---------------------------------------------------------------------------
# iOS extraction: embedded frameworks' Info.plist files
# ---------------------------------------------------------------------------


def _ios_add_package(packages: set, plist: dict):
    bundle_name = plist.get("CFBundleName")
    version = plist.get("CFBundleShortVersionString")
    bundle_identifier = plist.get("CFBundleIdentifier", "")

    if bundle_name and version:
        packages.add(f"{bundle_name}@{version}@{bundle_identifier}")


def _ios_extract_from_archive(zf: zipfile.ZipFile, packages: set):
    for name in zf.namelist():
        if not name.endswith("Info.plist"):
            continue

        try:
            plist = plistlib.loads(zf.read(name))
        except (KeyError, zipfile.BadZipFile, OSError, plistlib.InvalidFileException) as e:
            logger.warning("Skipping %s: %s", name, e)
            continue

        _ios_add_package(packages, plist)


def _ios_extract_from_directory(base_path: str, packages: set):
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

        _ios_add_package(packages, plist)


# ---------------------------------------------------------------------------
# Android extraction: build-embedded dependency metadata
# ---------------------------------------------------------------------------


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


def _android_classify(rel_path: str):
    parts = rel_path.replace("\\", "/").split("/")

    if parts[-1] == "pom.properties" and "META-INF" in parts and "maven" in parts:
        return _from_pom_properties

    if len(parts) == 2 and parts[0] == "META-INF" and parts[1].endswith(".version"):
        return _from_dependency_version_file

    return None


def _android_extract_from_archive(zf: zipfile.ZipFile, packages: set):
    for name in zf.namelist():
        handler = _android_classify(name)
        if handler is None:
            continue

        try:
            data = zf.read(name)
        except (KeyError, zipfile.BadZipFile, OSError) as e:
            logger.warning("Skipping %s: %s", name, e)
            continue

        component = handler(data, name)
        if component:
            packages.add("{}:{}@{}".format(*component))


def _android_extract_from_directory(base_path: str, packages: set):
    for root, _, files in os.walk(base_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, base_path)

            handler = _android_classify(rel_path)
            if handler is None:
                continue

            try:
                with open(file_path, "rb") as f:
                    data = f.read()
            except OSError as e:
                logger.warning("Skipping %s: %s", file_path, e)
                continue

            component = handler(data, rel_path)
            if component:
                packages.add("{}:{}@{}".format(*component))


def extract_packages(base_path: str, platform: str):
    """Extract components from a raw .apk/.ipa or an extracted app directory."""
    packages = set()
    if os.path.isdir(base_path):
        extractor = (
            _android_extract_from_directory
            if platform == "android"
            else _ios_extract_from_directory
        )
        extractor(base_path, packages)
        return sorted(packages)

    try:
        zf = zipfile.ZipFile(base_path)
    except (zipfile.BadZipFile, OSError) as e:
        raise ValueError(f"failed to open {base_path} as a zip archive: {e}") from e

    with zf:
        extractor = (
            _android_extract_from_archive
            if platform == "android"
            else _ios_extract_from_archive
        )
        extractor(zf, packages)

    return sorted(packages)

