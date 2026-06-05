"""
HEEL — optional data-classification enrichment (spec §8). Standalone, swappable, generic.

OPTIONAL (HEEL is fully functional with it OFF), GENERIC (no binding to any external framework
or runtime-governance system), and ANNOTATIVE ONLY (it enforces nothing at runtime and is not
runtime governance). Default is a simple field-name/shape heuristic; the `Classifier` interface
is the documented adapter point for a swap-in.
"""
from __future__ import annotations

from .contracts import AbuseVector, Category


class Classifier:
    """Adapter interface. Implement `classify(vector) -> {data_classes, obligations}`."""
    def classify(self, vector: AbuseVector) -> dict:
        raise NotImplementedError


_PII_CATEGORIES = {Category.DATA_HARVESTING, Category.COMPLIANCE_BOUNDARY, Category.IDENTITY_ACCOUNT}


class DefaultHeuristicClassifier(Classifier):
    """Field-name / category / scenario-hint heuristic. No external framework."""
    def classify(self, vector: AbuseVector) -> dict:
        repro = vector.reproduction or {}
        hint = (repro.get("classification_impact") or "")
        data_classes, obligations = [], []
        if vector.category in _PII_CATEGORIES or "pii" in hint or "tenant" in str(repro):
            data_classes.append("personal_data")
            obligations += ["access_control", "data_subject_rights", "breach_notification_if_exfiltrated"]
        if vector.category == Category.COMPLIANCE_BOUNDARY:
            obligations += ["retention_limits", "audit_logging", "residency"]
        if vector.category == Category.AGENT_MCP_SURFACE and "retrieval" in vector.affordance_id:
            data_classes.append("personal_data")
            obligations.append("cross_tenant_isolation")
        return {"data_classes": sorted(set(data_classes)), "obligations": sorted(set(obligations))}


def enrich(findings, classifier: Classifier | None = None, enabled: bool = False) -> None:
    """Annotate vectors. NO-OP unless enabled (optional by design)."""
    if not enabled:
        return
    classifier = classifier or DefaultHeuristicClassifier()
    for v in findings:
        ann = classifier.classify(v)
        if ann["data_classes"] or ann["obligations"]:
            v.classification_impact = {"data_classes": ann["data_classes"]}
            v.obligation_impact = {"obligations": ann["obligations"]}
