"""Dependency graph helpers and PNG rendering (Graphviz) of vulnerable dependency paths."""

import html
import logging
import os
import re
import shutil

from reverse_mob_sca.severity import SEVERITY_FILL, SEVERITY_ORDER, max_severity
from reverse_mob_sca.validate import component_key

logger = logging.getLogger("mobile-sca")

# Max vulnerability rows listed per component node; the rest is summarized
MAX_VULN_ROWS = 20
# Severity fills dark enough to need white text
DARK_SEVERITIES = {"Critical", "High"}
_UNSAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def transitive_closure(edges: dict):
    """Map each parent key -> set of all keys reachable from it (cycle-safe)."""
    result = {}
    for start in edges:
        seen, stack = set(), list(edges[start])
        while stack:
            node = stack.pop()
            if node not in seen:
                seen.add(node)
                stack.extend(edges.get(node, ()))
        seen.discard(start)
        result[start] = seen
    return result


def dot_available():
    return shutil.which("dot") is not None


def _esc(value):
    return html.escape(str(value), quote=True)


def _vuln_sort_key(vuln: dict):
    return (-(vuln["cvssScore"] if vuln["cvssScore"] is not None else -1), vuln["cve"])


def _component_label(component: dict, vulnerable_deps: int):
    lines = [f"<b>{_esc(component['name'])}</b>", _esc(component["version"])]
    details = [component["relation"]]
    if component["vulnerabilities"]:
        details.append(f"{len(component['vulnerabilities'])} vuln(s)")
    if vulnerable_deps:
        details.append(f"{vulnerable_deps} vulnerable dep(s)")
    lines.append(f'<font point-size="9">{_esc(" · ".join(details))}</font>')
    return f"<{'<br/>'.join(lines)}>"


def _severity_text(severity: str):
    """Severity label, white on the dark (Critical/High) fills."""
    if severity in DARK_SEVERITIES:
        return f'<font color="#FFFFFF">{_esc(severity)}</font>'
    return _esc(severity)


def _vulns_label(vulns: list):
    rows = ['<tr><td><b>ID</b></td><td><b>CVSS</b></td><td><b>Severity</b></td></tr>']
    ordered = sorted(vulns, key=_vuln_sort_key)
    for vuln in ordered[:MAX_VULN_ROWS]:
        color = SEVERITY_FILL.get(vuln["severity"])
        bg = f' bgcolor="#{color}"' if color else ""
        score = "" if vuln["cvssScore"] is None else f"{vuln['cvssScore']:.1f}"
        rows.append(
            f'<tr><td align="left">{_esc(vuln["cve"])}</td><td>{_esc(score)}</td>'
            f"<td{bg}>{_severity_text(vuln['severity'])}</td></tr>"
        )
    if len(ordered) > MAX_VULN_ROWS:
        rows.append(f'<tr><td colspan="3"><i>… {len(ordered) - MAX_VULN_ROWS} more</i></td></tr>')
    return f'<<table border="0" cellborder="1" cellspacing="0" cellpadding="3">{"".join(rows)}</table>>'


def _legend_label():
    """Graph label explaining node fills, borders and edges."""
    swatches = "".join(
        f'<td bgcolor="#{SEVERITY_FILL[sev]}" border="1">'
        f"{_severity_text(sev)}</td>"
        for sev in SEVERITY_ORDER
        if sev in SEVERITY_FILL
    )
    swatches += '<td bgcolor="#D9D9D9" border="1">Unknown</td>'
    styles = (
        '<td border="1" bgcolor="#FFFFFF">only a path to a vulnerable dependency</td>'
        '<td border="1">observed in the app</td>'
        '<td border="1" style="dashed">not observed (version as declared upstream)</td>'
        '<td border="2">graph root</td>'
    )
    return (
        '<<font point-size="8"><table border="0" cellborder="0" cellspacing="2" cellpadding="2">'
        '<tr><td align="left"><b>Legend</b></td></tr>'
        '<tr><td align="left"><table border="0" cellspacing="2" cellpadding="2">'
        f'<tr><td align="right"><i>Max severity</i></td>{swatches}</tr></table></td></tr>'
        '<tr><td align="left"><table border="0" cellspacing="2" cellpadding="2">'
        f'<tr><td align="right"><i>Component</i></td>{styles}</tr></table></td></tr>'
        '<tr><td align="left"><i>A</i> → <i>B</i>: A depends on B (<i>-t</i> only)    '
        '<font color="#C00000">┄</font> component\'s vulnerabilities (sorted by CVSS)</td></tr>'
        "</table></font>>"
    )


def _filename(component: dict, used: set):
    base = _UNSAFE_FILENAME_RE.sub("_", f"{component['name']}@{component['version']}").strip("._") or "component"
    name, n = base, 1
    while name.lower() in used:
        n += 1
        name = f"{base}_{n}"
    used.add(name.lower())
    return name


def _render(root, members: set, by_key: dict, edges: dict, vulnerable_deps: dict, path: str):
    import graphviz

    dot = graphviz.Digraph(
        graph_attr={"rankdir": "LR", "dpi": "150", "fontname": "Helvetica", "nodesep": "0.3",
                    "label": _legend_label(), "labelloc": "b", "labeljust": "l"},
        node_attr={"fontname": "Helvetica", "fontsize": "11"},
        edge_attr={"fontname": "Helvetica"},
    )
    ids = {key: f"c{i}" for i, key in enumerate(sorted(members, key=str))}

    for key, node_id in ids.items():
        component = by_key[key]
        vulns = component["vulnerabilities"]
        severity = max_severity(vulns)
        attrs = {"shape": "box", "style": "rounded,filled", "fillcolor": "#FFFFFF"}
        if vulns:
            attrs["fillcolor"] = f"#{SEVERITY_FILL.get(severity, 'D9D9D9')}"
            # Readable text on dark fills
            if severity in DARK_SEVERITIES:
                attrs["fontcolor"] = "#FFFFFF"
        if component["relation"] != "observed":
            # Not seen in the app: version is as declared upstream
            attrs["style"] += ",dashed"
        if key == root:
            attrs["penwidth"] = "2"
        dot.node(node_id, _component_label(component, vulnerable_deps.get(key, 0)), **attrs)

        if vulns:
            dot.node(f"{node_id}_v", _vulns_label(vulns), shape="plain", fontsize="9")
            dot.edge(node_id, f"{node_id}_v", style="dotted", color="#C00000", arrowhead="none")

    for parent in members:
        for child in edges.get(parent, ()):
            if child in members:
                dot.edge(ids[parent], ids[child])

    dot.render(outfile=path, format="png", cleanup=True)


def write_graphs(data: list, edges: dict, directory: str):
    """Write one PNG per vulnerable dependency tree into directory.

    Only vulnerable components and the dependency paths leading to them are drawn: a
    component is kept if it has vulnerabilities or (transitively) depends on one that
    does. Each graph is rooted at a kept component that no other kept component depends
    on, and contains all its kept descendants (shared subtrees repeat across graphs).
    Returns the list of written paths.
    """
    by_key = {component_key(c["name"], c["version"]): c for c in data if c["version"]}
    edges = {
        parent: {child for child in children if child in by_key}
        for parent, children in edges.items()
        if parent in by_key
    }
    closure = transitive_closure(edges)

    vulnerable = {key for key, c in by_key.items() if c["vulnerabilities"]}
    vulnerable_deps = {key: len(closure.get(key, set()) & vulnerable) for key in by_key}
    kept = vulnerable | {key for key, count in vulnerable_deps.items() if count}
    if not kept:
        logger.info("No vulnerable components, no graphs written")
        return []

    has_kept_parent = {child for parent in kept for child in edges.get(parent, ()) if child in kept}
    roots = [key for key in kept if key not in has_kept_parent]
    covered = set()
    for key in roots:
        covered |= {key} | (closure.get(key, set()) & kept)
    # Pure cycles have no root: seed them from any uncovered node
    for key in sorted(kept - covered, key=str):
        if key not in covered:
            roots.append(key)
            covered |= {key} | (closure.get(key, set()) & kept)

    def root_rank(key):
        severities = [max_severity(by_key[k]["vulnerabilities"]) for k in {key} | (closure.get(key, set()) & kept)]
        worst = min((SEVERITY_ORDER.index(s) for s in severities if s), default=len(SEVERITY_ORDER))
        return worst, by_key[key]["name"].lower()

    os.makedirs(directory, exist_ok=True)
    written, used = [], set()
    for root in sorted(roots, key=root_rank):
        members = {root} | (closure.get(root, set()) & kept)
        path = os.path.join(directory, f"{_filename(by_key[root], used)}.png")
        _render(root, members, by_key, edges, vulnerable_deps, path)
        logger.debug("Wrote graph %s (%d components)", path, len(members))
        written.append(path)

    logger.info("Wrote %d dependency graph(s) to %s", len(written), directory)
    return written
