import logging
import re

logger = logging.getLogger("mobile-sca")

# Expected input line formats. Character sets are deliberately conservative: anything
# outside them (whitespace, PURL delimiters such as '/', '?', '#', extra '@'/':') would
# yield a malformed or ambiguous PURL, so such lines are rejected before querying any source.
_VERSION = r"[A-Za-z0-9][A-Za-z0-9._+~-]*"
ANDROID_ENTRY_RE = re.compile(
    r"^(?P<group>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r":(?P<artifact>[A-Za-z0-9][A-Za-z0-9._-]*)"
    rf"@(?P<version>{_VERSION})$"
)
IOS_ENTRY_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._+-]*)"
    rf"@(?P<version>{_VERSION})"
    r"(?:@(?P<bundle_identifier>[A-Za-z0-9._-]*))?$"
)
EXPECTED_FORMAT = {
    "android": "group:artifact@version",
    "ios": "name@version[@bundle_identifier]",
}

# Provenance of a component, strongest first: seen in the app, or pulled in (as declared
# by deps.dev's resolved graph) as a direct/indirect dependency of an observed component.
RELATION_RANK = {"observed": 0, "direct": 1, "indirect": 2}


def component_key(name: str, version: str):
    """Case-insensitive identity used to merge results across sources (version may be None)."""
    return name.lower(), version.lower() if version else None


def validate_entry(line: str, platform: str, relation: str = "observed"):
    """Return an entry dict for a well-formed line, raise ValueError otherwise."""
    if any(c.isspace() for c in line):
        raise ValueError("contains whitespace")

    regex = ANDROID_ENTRY_RE if platform == "android" else IOS_ENTRY_RE
    match = regex.match(line)
    if not match:
        raise ValueError(f"does not match expected format {EXPECTED_FORMAT[platform]}")

    if platform == "android":
        name = f"{match['group']}:{match['artifact']}"
        purl = f"pkg:maven/{match['group']}/{match['artifact']}@{match['version']}"
        bundle_identifier = None
    else:
        name = match["name"]
        purl = f"pkg:cocoapods/{match['name']}@{match['version']}"
        bundle_identifier = match["bundle_identifier"] or None

    return {
        "line": line,
        "purl": purl,
        "name": name,
        "version": match["version"],
        "bundle_identifier": bundle_identifier,
        "relation": relation,
        "via": set(),
        # False for declared dependencies whose version couldn't be determined (iOS -t)
        "resolved": True,
        # iOS -t: parent -> declared version requirements, and observed mismatches
        "requirements": {},
        "constraint_violations": [],
    }


def unresolved_entry(name: str, platform: str, relation: str):
    """Entry for a declared dependency with unknown version (never queried)."""
    # Validate the name with a placeholder version, then drop it
    entry = validate_entry(f"{name}@0", platform, relation)
    entry.update({"line": None, "purl": None, "version": None, "resolved": False})
    return entry


def validate_entries(lines: list, platform: str, source: str):
    """Validate every entry upfront; malformed ones are reported and dropped."""
    entries = []
    rejected = 0
    for lineno, line in lines:
        try:
            entries.append(validate_entry(line, platform))
        except ValueError as e:
            rejected += 1
            logger.warning("Rejecting %s:%s %r: %s", source, lineno, line, e)

    if rejected:
        logger.warning(
            "%d/%d entries rejected (expected format: %s)",
            rejected,
            len(lines),
            EXPECTED_FORMAT[platform],
        )

    return entries
