import argparse
import json
import logging
import os
import sys

from reverse_mob_sca import cocoapods, depsdev
from reverse_mob_sca.extract import extract_packages
from reverse_mob_sca.net import make_session
from reverse_mob_sca.sources import osv, sonatype
from reverse_mob_sca.validate import component_key, validate_entries

logger = logging.getLogger("mobile-sca")

SOURCES = (sonatype.NAME, osv.NAME)
# Advisory sources usable per platform (OSV has no CocoaPods ecosystem)
PLATFORM_SOURCES = {
    "android": {sonatype.NAME, osv.NAME},
    "ios": {sonatype.NAME},
}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="reverse-mob-sca",
        description="Black-box SCA for Android/iOS apps: enumerate third-party components "
        "(from the app itself or from a pre-built list) and query vulnerability databases "
        "(Sonatype OSS Index, OSV.dev) for known CVEs. Sonatype credentials are read from "
        "the SONATYPE_USERNAME and SONATYPE_API_KEY environment variables.",
    )
    parser.add_argument(
        "-p",
        "--platform",
        dest="platform",
        required=True,
        choices=["android", "ios"],
        type=str,
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "-a",
        "--app",
        dest="app",
        type=str,
        help="Raw .apk/.ipa file or an already-extracted APK/app bundle directory. "
        "Android: reads META-INF/<group>_<artifact>.version and META-INF/maven/*/*/pom.properties "
        "(best-effort, only catches dependencies embedding these markers). "
        "iOS: reads embedded frameworks' Info.plist files.",
    )
    source.add_argument(
        "-f",
        "--file",
        dest="packages_list",
        type=str,
        help="Pre-built component list, one entry per line. "
        "Android: group:artifact@version (e.g. from MobSF SBOM analysis or --extract-only). "
        "iOS: name@version[@bundle_identifier] (e.g. from --extract-only).",
    )

    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        type=str,
        help="Path to write JSON results (required unless --extract-only). "
        "With --extract-only, path to write the component list (default: stdout).",
    )
    parser.add_argument(
        "-s",
        "--sources",
        dest="sources",
        type=str,
        default=",".join(SOURCES),
        help=f"Comma-separated advisory sources to query, among: {', '.join(SOURCES)} "
        "(default: all). iOS supports sonatype only.",
    )
    parser.add_argument(
        "-t",
        "--transitive",
        dest="transitive",
        action="store_true",
        help="Also resolve child dependencies of each component. Android: transitive graph "
        "via deps.dev, children checked at the version declared upstream (may differ from what "
        "ships: Gradle conflict resolution, R8). iOS: podspecs from CocoaPods Trunk; only declare "
        "version constraints, so children are linked to their parents and checked against the "
        "constraint when observed in the app, otherwise reported as unresolved (not queried).",
    )
    parser.add_argument(
        "--extract-only",
        dest="extract_only",
        action="store_true",
        help="Only extract the component list from --app (plus transitive children with "
        "--transitive) and write it out, without querying advisory sources. "
        "The result can be reviewed/edited and fed back via -f.",
    )
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
    return parser


def parse_sources(parser, args):
    requested = [s.strip() for s in args.sources.split(",") if s.strip()]
    unknown = set(requested) - set(SOURCES)
    if unknown or not requested:
        parser.error(f"--sources: unknown/empty source(s) {sorted(unknown)}, choose among {', '.join(SOURCES)}")

    supported = [s for s in requested if s in PLATFORM_SOURCES[args.platform]]
    for s in requested:
        if s not in supported:
            logger.warning("Source %s doesn't support --platform %s, ignoring it", s, args.platform)
    if not supported:
        supported = sorted(PLATFORM_SOURCES[args.platform])
        logger.warning("Falling back to: %s", ", ".join(supported))
    return supported


def load_lines(args):
    """Return [(line_number_or_index, line), ...] and a label for the input source."""
    if args.app:
        if not os.path.exists(args.app):
            logger.error("Path does not exist: %s", args.app)
            sys.exit(1)

        try:
            packages = extract_packages(args.app, args.platform)
        except ValueError as e:
            logger.error("%s", e)
            sys.exit(1)

        logger.info("Extracted %d components from %s", len(packages), args.app)
        return list(enumerate(packages, 1)), args.app

    if not os.path.exists(args.packages_list):
        logger.error("File does not exist: %s", args.packages_list)
        sys.exit(1)

    try:
        with open(args.packages_list, "r") as f:
            lines = [
                (lineno, line.strip())
                for lineno, line in enumerate(f, 1)
                if line.strip()
            ]
    except OSError as e:
        logger.error("Failed to read %s: %s", args.packages_list, e)
        sys.exit(1)

    logger.info("Loaded %d components from %s", len(lines), args.packages_list)
    return lines, args.packages_list


def _ids(vuln: dict):
    return {vuln["cve"], *vuln["aliases"]}


def merge_vulnerabilities(per_source: list):
    """Dedupe [(source, vuln), ...] by CVE id, falling back to alias overlap."""
    merged = []
    for source, vuln in per_source:
        for existing in merged:
            if _ids(existing) & _ids(vuln):
                existing["sources"] = sorted(set(existing["sources"]) | {source})
                existing["aliases"] = sorted((_ids(existing) | _ids(vuln)) - {existing["cve"]})
                existing["references"] += [r for r in vuln["references"] if r not in existing["references"]]
                if existing["cvssScore"] is None and vuln["cvssScore"] is not None:
                    existing["cvssScore"] = vuln["cvssScore"]
                    existing["severity"] = vuln["severity"]
                break
        else:
            merged.append({**vuln, "references": list(vuln["references"]), "sources": [source]})
    return merged


def build_results(entries: list, platform: str, results: dict, descendants: dict):
    """Combine per-source results into one record per component."""
    components = {}
    for entry in entries:
        key = component_key(entry["name"], entry["version"])
        found = [(source, results[source][key]) for source in results if key in results[source]]

        description = next((r.get("description") for _, r in found if r.get("description")), "")
        reference = next((r.get("reference") for _, r in found if r.get("reference")), "")
        components[key] = {
            "platform": platform,
            "name": entry["name"],
            "version": entry["version"],
            "bundle_identifier": entry["bundle_identifier"],
            "resolved": entry["resolved"],
            "relation": entry["relation"],
            "via": sorted(entry["via"]),
            "sources": [source for source, _ in found],
            "description": description,
            "reference": reference,
            "vulnerabilities": merge_vulnerabilities(
                [(source, v) for source, r in found for v in r["vulnerabilities"]]
            ),
        }
        if platform == "ios":
            components[key]["requirements"] = entry["requirements"]
            components[key]["constraint_violations"] = entry["constraint_violations"]

    # mvnrepository-style "vulnerabilities from dependencies" rollup
    for key, component in components.items():
        rollup = []
        for child_key in sorted(descendants.get(key, ())):
            child = components.get(child_key)
            if child and child["vulnerabilities"]:
                rollup.append(
                    {
                        "name": child["name"],
                        "version": child["version"],
                        "ids": [v["cve"] for v in child["vulnerabilities"]],
                    }
                )
        component["dependency_vulnerabilities"] = rollup

    return list(components.values())


def write_list(entries: list, output: str):
    out = "".join(f"{entry['line']}\n" for entry in sorted(entries, key=lambda e: e["line"]))
    if not output:
        sys.stdout.write(out)
        return

    try:
        with open(output, "w") as f:
            f.write(out)
    except OSError as e:
        logger.error("Failed to write output to %s: %s", output, e)
        sys.exit(1)
    logger.info("Wrote %d components to %s", len(entries), output)


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.extract_only and not args.app:
        parser.error("--extract-only requires -a/--app")
    if not args.extract_only and not args.output:
        parser.error("-o/--output is required unless --extract-only is set")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    platform = args.platform
    sources = [] if args.extract_only else parse_sources(parser, args)
    transitive = args.transitive

    if sonatype.NAME in sources:
        username = os.environ.get("SONATYPE_USERNAME")
        api_key = os.environ.get("SONATYPE_API_KEY")
        if not username or not api_key:
            logger.error("SONATYPE_USERNAME and SONATYPE_API_KEY environment variables must be set")
            sys.exit(1)

    lines, source = load_lines(args)
    if not lines:
        logger.error("No components found in %s", source)
        sys.exit(1)

    if args.extract_only and not transitive:
        # Raw dump: entries are left unvalidated so they can be reviewed/fixed by hand
        write_list([{"line": line} for _, line in lines], args.output)
        return

    entries = validate_entries(lines, platform, source)
    if not entries:
        logger.error("No valid components in %s", source)
        sys.exit(1)

    session = make_session(args.proxy)

    descendants = {}
    if transitive:
        resolver = depsdev if platform == "android" else cocoapods
        entries, descendants = resolver.resolve(session, entries)

    queryable = [e for e in entries if e["resolved"]]

    if args.extract_only:
        # Unresolved children have no version to write; they were logged by the resolver
        write_list(queryable, args.output)
        return

    logger.info(
        "Checking %d components (platform=%s, sources=%s)",
        len(queryable),
        platform,
        ",".join(sources),
    )

    results = {}
    try:
        for name in sources:
            if name == sonatype.NAME:
                results[name] = {}
                sonatype.query(session, queryable, platform, username, api_key, data=results[name])
            elif name == osv.NAME:
                results[name] = osv.query(session, queryable, platform)
    except KeyboardInterrupt:
        logger.warning("Interrupted by user, writing partial results to %s", args.output)

    data = build_results(entries, platform, results, descendants)

    try:
        with open(args.output, "w") as f:
            json.dump(data, f, indent=4)
    except OSError as e:
        logger.error("Failed to write output to %s: %s", args.output, e)
        sys.exit(1)

    vulnerable = sum(1 for c in data if c["vulnerabilities"])
    logger.info("Wrote %d results (%d vulnerable) to %s", len(data), vulnerable, args.output)


if __name__ == "__main__":
    main()
