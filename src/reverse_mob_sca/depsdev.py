import logging
from urllib.parse import quote

import requests

from reverse_mob_sca.net import REQUEST_TIMEOUT
from reverse_mob_sca.validate import RELATION_RANK, component_key, validate_entry

logger = logging.getLogger("mobile-sca")

DEPENDENCIES_URL = "https://api.deps.dev/v3/systems/maven/packages/{}/versions/{}:dependencies"


def _descendants(nodes: list, edges: list):
    """Map node index -> set of all transitively reachable node indexes."""
    children = {}
    for edge in edges:
        children.setdefault(edge["fromNode"], set()).add(edge["toNode"])

    result = {}
    for start in range(len(nodes)):
        seen, stack = set(), list(children.get(start, ()))
        while stack:
            node = stack.pop()
            if node not in seen:
                seen.add(node)
                stack.extend(children.get(node, ()))
        result[start] = seen
    return result


def resolve(session, entries: list):
    """Expand Android entries with their transitive dependencies as declared by deps.dev.

    Returns (entries, descendants) where descendants maps a component key to the set of
    component keys it (transitively) pulls in. Versions of non-observed children are
    taken as declared in the resolved graph, so they may differ from what actually ships.
    """
    by_key = {component_key(e["name"], e["version"]): e for e in entries}
    descendants = {}

    roots = list(by_key.values())
    for idx, root in enumerate(roots, 1):
        url = DEPENDENCIES_URL.format(quote(root["name"], safe=""), quote(root["version"], safe=""))
        logger.debug("Resolving dependencies of %s (%d/%d)", root["purl"], idx, len(roots))
        try:
            response = session.get(url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 404:
                logger.warning("deps.dev doesn't know %s, skipping transitive resolution", root["purl"])
                continue
            response.raise_for_status()
            graph = response.json()
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.warning("deps.dev lookup failed for %s: %s", root["purl"], e)
            continue

        nodes = graph.get("nodes", [])
        keys = []
        for node in nodes:
            version_key = node.get("versionKey", {})
            name, version = version_key.get("name", ""), version_key.get("version", "")
            keys.append(component_key(name, version))

            if node.get("relation") == "SELF":
                continue

            relation = "direct" if node.get("relation") == "DIRECT" else "indirect"
            key = keys[-1]
            if key not in by_key:
                try:
                    by_key[key] = validate_entry(f"{name}@{version}", "android", relation)
                except ValueError as e:
                    logger.warning("Rejecting deps.dev node %s@%s: %s", name, version, e)
                    continue

            child = by_key[key]
            if RELATION_RANK[relation] < RELATION_RANK[child["relation"]]:
                child["relation"] = relation
            child["via"].add(root["name"])

        for node_idx, reachable in _descendants(nodes, graph.get("edges", [])).items():
            if reachable:
                descendants.setdefault(keys[node_idx], set()).update(keys[i] for i in reachable)

    added = len(by_key) - len(roots)
    logger.info("Resolved %d additional transitive components via deps.dev", added)
    return list(by_key.values()), descendants
