import logging

from cvss import CVSS3, CVSS4
from cvss.exceptions import CVSSError

logger = logging.getLogger("mobile-sca")

# GHSA qualitative labels, used when no parsable CVSS vector is available
_GHSA_LABELS = {
    "LOW": "Low",
    "MODERATE": "Medium",
    "MEDIUM": "Medium",
    "HIGH": "High",
    "CRITICAL": "Critical",
}


def get_severity_by_cvss_score(score: float):
    if score is None:
        return "Unknown"
    if 0.0 <= score < 0.1:
        return "Informational"
    if 0.1 <= score <= 3.9:
        return "Low"
    if 4.0 <= score <= 6.9:
        return "Medium"
    if 7.0 <= score <= 8.9:
        return "High"
    if 9.0 <= score <= 10:
        return "Critical"

    return "Unknown"


def score_from_vector(vector: str):
    """Base score of a CVSS v3.x/v4.0 vector string, None if unsupported/unparsable."""
    try:
        if vector.startswith("CVSS:4."):
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3."):
            return float(CVSS3(vector).scores()[0])
    except CVSSError as e:
        logger.debug("Unparsable CVSS vector %r: %s", vector, e)
    return None


def severity_from_label(label: str):
    return _GHSA_LABELS.get((label or "").upper(), "Unknown")
