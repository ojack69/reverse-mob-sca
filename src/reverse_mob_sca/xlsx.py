"""Excel (.xlsx) export of the merged results."""

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]
SEVERITY_FILL = {
    "Critical": "C00000",
    "High": "FF0000",
    "Medium": "FFC000",
    "Low": "92D050",
    "Informational": "BDD7EE",
}
MAX_COL_WIDTH = 80


def _cell_value(value):
    """Flatten to a cell-safe value: lists joined, control chars stripped."""
    if value is None:
        return None
    if isinstance(value, bool | int | float):
        return value
    if isinstance(value, list | tuple):
        value = "\n".join(str(v) for v in value)
    elif isinstance(value, dict):
        value = "\n".join(f"{k}: {', '.join(map(str, v)) if isinstance(v, list) else v}" for k, v in value.items())
    return ILLEGAL_CHARACTERS_RE.sub("", str(value))


def _append(ws, row):
    ws.append([_cell_value(v) for v in row])
    # openpyxl treats strings starting with "=" as formulas: force advisory/app-derived
    # text to plain strings so it can't inject formulas into the analyst's spreadsheet
    for cell in ws[ws.max_row]:
        if isinstance(cell.value, str):
            cell.data_type = "s"


def _finalize(ws, severity_col=None):
    for cell in ws[1]:
        cell.font = Font(bold=True)
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions

    for idx, column in enumerate(ws.columns, start=1):
        width = max((len(line) for c in column if c.value is not None for line in str(c.value).split("\n")), default=0)
        ws.column_dimensions[get_column_letter(idx)].width = min(width + 2, MAX_COL_WIDTH)

    if severity_col is not None:
        for row in ws.iter_rows(min_row=2, min_col=severity_col, max_col=severity_col):
            color = SEVERITY_FILL.get(row[0].value)
            if color:
                row[0].fill = PatternFill("solid", start_color=color)


def _max_severity(vulns):
    labels = {v["severity"] for v in vulns}
    return next((s for s in SEVERITY_ORDER if s in labels), None)


def write_xlsx(data: list, path: str):
    ios = any(c["platform"] == "ios" for c in data)
    wb = Workbook()

    ws = wb.active
    ws.title = "Components"
    header = [
        "Name", "Version", "Bundle identifier", "Resolved", "Relation", "Via", "Sources",
        "Vulnerabilities", "Max severity", "Max CVSS", "IDs", "Dependency vulnerabilities",
        "Description", "Reference",
    ]
    if ios:
        header += ["Requirements", "Constraint violations"]
    ws.append(header)
    for c in data:
        vulns = c["vulnerabilities"]
        scores = [v["cvssScore"] for v in vulns if v["cvssScore"] is not None]
        row = [
            c["name"], c["version"], c["bundle_identifier"], c["resolved"], c["relation"], c["via"],
            c["sources"], len(vulns), _max_severity(vulns), max(scores) if scores else None,
            [v["cve"] for v in vulns],
            [f"{d['name']}@{d['version']}: {', '.join(d['ids'])}" for d in c["dependency_vulnerabilities"]],
            c["description"], c["reference"],
        ]
        if ios:
            row += [c.get("requirements"), c.get("constraint_violations")]
        _append(ws, row)
    _finalize(ws, severity_col=header.index("Max severity") + 1)

    ws = wb.create_sheet("Vulnerabilities")
    header = [
        "Name", "Version", "Relation", "Via", "ID", "Aliases", "CVSS", "Severity", "Sources", "References",
    ]
    ws.append(header)
    rows = [
        (c, v)
        for c in data
        for v in c["vulnerabilities"]
    ]
    rows.sort(key=lambda cv: (-(cv[1]["cvssScore"] or -1), cv[0]["name"].lower(), cv[1]["cve"]))
    for c, v in rows:
        _append(ws, [
            c["name"], c["version"], c["relation"], c["via"], v["cve"], v["aliases"],
            v["cvssScore"], v["severity"], v["sources"], v["references"],
        ])
    _finalize(ws, severity_col=header.index("Severity") + 1)

    wb.save(path)
