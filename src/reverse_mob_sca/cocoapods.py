import hashlib
import logging
import re
from urllib.parse import quote

import requests

from reverse_mob_sca.net import REQUEST_TIMEOUT
from reverse_mob_sca.validate import component_key, unresolved_entry

logger = logging.getLogger("mobile-sca")

# CocoaPods Trunk podspecs, sharded by the first 3 hex chars of md5(pod name); the CDN
# redirects to jsDelivr.
PODSPEC_URL = "https://cdn.cocoapods.org/Specs/{}/{}/{}/{}/{}/{}.podspec.json"

# Frameworks whose CFBundleName differs from the pod name
FRAMEWORK_TO_POD = {
    "fblpromises": "PromisesObjC",
    "lottie": "lottie-ios",
}

_REQUIREMENT_RE = re.compile(r"^\s*(~>|>=|<=|!=|=|>|<)?\s*(\S+)\s*$")


# ---------------------------------------------------------------------------
# Version requirements (RubyGems/CocoaPods semantics)
# ---------------------------------------------------------------------------


def _parse_version(version: str):
    main, _, pre = version.partition("-")
    segments = []
    for seg in main.split("."):
        if seg.isdigit():
            segments.append(int(seg))
        else:
            # e.g. "1.0b1": treat the alphabetic tail as a pre-release marker
            digits = re.match(r"\d*", seg).group()
            segments.append(int(digits) if digits else 0)
            pre = pre or seg[len(digits):]
    return segments, pre


def compare_versions(a: str, b: str):
    """-1/0/1 comparison; a pre-release sorts before its release."""
    sa, pa = _parse_version(a)
    sb, pb = _parse_version(b)
    length = max(len(sa), len(sb))
    sa += [0] * (length - len(sa))
    sb += [0] * (length - len(sb))
    if sa != sb:
        return -1 if sa < sb else 1
    if pa == pb:
        return 0
    if not pa:
        return 1
    if not pb:
        return -1
    return -1 if pa < pb else 1


def _pessimistic_upper(version: str):
    segments, _ = _parse_version(version)
    if len(segments) > 1:
        segments = segments[:-1]
    segments[-1] += 1
    return ".".join(map(str, segments))


def satisfies(version: str, requirements: list):
    """True if version matches every requirement (empty list = any version)."""
    for requirement in requirements:
        match = _REQUIREMENT_RE.match(requirement)
        if not match:
            raise ValueError(f"unparsable requirement {requirement!r}")
        op, target = match.group(1) or "=", match.group(2)
        cmp = compare_versions(version, target)

        if op == "~>":
            ok = cmp >= 0 and compare_versions(version, _pessimistic_upper(target)) < 0
        else:
            ok = {
                "=": cmp == 0,
                "!=": cmp != 0,
                ">": cmp > 0,
                "<": cmp < 0,
                ">=": cmp >= 0,
                "<=": cmp <= 0,
            }[op]
        if not ok:
            return False
    return True


# ---------------------------------------------------------------------------
# Podspecs
# ---------------------------------------------------------------------------


def podspec_url(name: str, version: str):
    digest = hashlib.md5(name.encode()).hexdigest()
    return PODSPEC_URL.format(
        digest[0], digest[1], digest[2], quote(name, safe=""), quote(version, safe=""), quote(name, safe="")
    )


def _flatten_subspecs(spec: dict, prefix: str = ""):
    """Map subspec path (e.g. "Core/Extras") -> subspec dict."""
    index = {}
    for sub in spec.get("subspecs", []):
        path = f"{prefix}{sub['name']}"
        index[path] = sub
        index.update(_flatten_subspecs(sub, f"{path}/"))
    return index


def _default_subspecs(spec: dict, index: dict):
    default = spec.get("default_subspecs")
    if default is None:
        return set(p for p in index if "/" not in p)
    if isinstance(default, str):
        default = [default]
    return set(d for d in default if d != "none")


def declared_deps(spec: dict, subspecs: set = None):
    """Return {pod: (requirements, subspecs)} declared by spec and the selected subspecs.

    subspecs=None selects the spec's default subspecs (all top-level ones if unset).
    Dependencies on the pod's own subspecs are expanded in place; a subspec inherits
    its ancestors' dependencies.
    """
    own = spec["name"]
    index = _flatten_subspecs(spec)
    pending = set(_default_subspecs(spec, index) if subspecs is None else subspecs)

    selected = set()
    while pending:
        path = pending.pop()
        parts = path.split("/")
        for i in range(1, len(parts) + 1):
            ancestor = "/".join(parts[:i])
            if ancestor in index and ancestor not in selected:
                selected.add(ancestor)
                for dep in index[ancestor].get("dependencies") or {}:
                    base, _, sub = dep.partition("/")
                    if base == own and sub:
                        pending.add(sub)

    deps = {}
    for source in [spec] + [index[p] for p in sorted(selected)]:
        for dep, reqs in (source.get("dependencies") or {}).items():
            base, _, sub = dep.partition("/")
            if base == own:
                continue
            req_list, sub_set = deps.setdefault(base, ([], set()))
            req_list += [r for r in reqs if r not in req_list]
            if sub:
                sub_set.add(sub)
    return deps


def fetch_podspec(session, name: str, version: str, cache: dict):
    key = (name, version)
    if key in cache:
        return cache[key]

    spec = None
    try:
        response = session.get(podspec_url(name, version), timeout=REQUEST_TIMEOUT)
        if response.status_code == 404:
            logger.debug("No podspec on CocoaPods Trunk for %s %s", name, version)
        else:
            response.raise_for_status()
            spec = response.json()
    except (requests.exceptions.RequestException, ValueError) as e:
        logger.warning("CocoaPods Trunk lookup failed for %s %s: %s", name, version, e)

    cache[key] = spec
    return spec


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def resolve(session, entries: list):
    """Attach CocoaPods dependency info to observed iOS entries.

    Podspecs only declare version constraints, so a child's version is known only when
    the child itself was observed in the app; other declared children are returned as
    unresolved entries (version None) carrying their requirements, and are not recursed.
    Returns (entries, descendants) like depsdev.resolve.
    """
    observed = {}
    for entry in entries:
        pod = FRAMEWORK_TO_POD.get(entry["name"].lower(), entry["name"])
        entry["pod"] = pod
        observed[pod.lower()] = entry

    unresolved = {}
    edges = {}  # parent component key -> set of child component keys
    requested = {pod: set() for pod in observed}  # subspecs asked for by parents
    processed = {}
    cache = {}
    missing = 0

    # Iterate to a fixpoint: a parent may request a non-default subspec of an observed
    # pod, which can declare further dependencies.
    changed = True
    while changed:
        changed = False
        for pod_lower, entry in observed.items():
            wanted = frozenset(requested[pod_lower])
            if processed.get(pod_lower) == wanted:
                continue
            first_pass = pod_lower not in processed
            processed[pod_lower] = wanted

            spec = fetch_podspec(session, entry["pod"], entry["version"], cache)
            if spec is None:
                missing += first_pass
                continue

            # Which subspecs the app actually uses is unknown: over-approximate with the
            # defaults plus whatever parents explicitly asked for.
            deps = declared_deps(spec)
            if wanted:
                for dep_pod, (reqs, subs) in declared_deps(spec, set(wanted)).items():
                    base_reqs, base_subs = deps.setdefault(dep_pod, ([], set()))
                    base_reqs += [r for r in reqs if r not in base_reqs]
                    base_subs |= subs

            parent_key = component_key(entry["name"], entry["version"])
            for child_pod, (reqs, subs) in deps.items():
                child = observed.get(child_pod.lower())
                if child is not None:
                    if not subs <= requested[child_pod.lower()]:
                        requested[child_pod.lower()] |= subs
                        changed = True
                    _check_requirements(child, entry["name"], reqs)
                else:
                    child = unresolved.get(child_pod.lower())
                    if child is None:
                        try:
                            child = unresolved_entry(child_pod, "ios", "direct")
                        except ValueError as e:
                            logger.warning("Rejecting declared dependency %s: %s", child_pod, e)
                            continue
                        unresolved[child_pod.lower()] = child

                child["via"].add(entry["name"])
                child["requirements"][entry["name"]] = reqs
                edges.setdefault(parent_key, set()).add(component_key(child["name"], child["version"]))

    if missing:
        logger.info(
            "%d/%d observed components not found on CocoaPods Trunk (not pods, SPM/vendored, "
            "or plist version differs from the pod version)",
            missing,
            len(observed),
        )
    for child in unresolved.values():
        logger.warning(
            "Unresolved dependency %s (%s) declared by %s: not observed in the app, version unknown",
            child["name"],
            "; ".join(f"{p}: {', '.join(r) or 'any'}" for p, r in sorted(child["requirements"].items())),
            ", ".join(sorted(child["via"])),
        )

    descendants = {}
    for start in edges:
        seen, stack = set(), list(edges[start])
        while stack:
            node = stack.pop()
            if node not in seen:
                seen.add(node)
                stack.extend(edges.get(node, ()))
        descendants[start] = seen

    for entry in entries:
        entry.pop("pod", None)

    logger.info(
        "CocoaPods Trunk: %d dependency edges, %d unresolved declared dependencies",
        sum(len(c) for c in edges.values()),
        len(unresolved),
    )
    return entries + list(unresolved.values()), descendants


def _check_requirements(child: dict, parent: str, reqs: list):
    try:
        ok = satisfies(child["version"], reqs)
    except ValueError as e:
        logger.warning("Cannot check %s requirement from %s: %s", child["name"], parent, e)
        return
    if not ok:
        violation = {"via": parent, "requirements": reqs, "observed": child["version"]}
        if violation not in child["constraint_violations"]:
            child["constraint_violations"].append(violation)
            logger.warning(
                "%s %s doesn't satisfy %s required by %s (misread version or vendored fork?)",
                child["name"],
                child["version"],
                ", ".join(reqs),
                parent,
            )
