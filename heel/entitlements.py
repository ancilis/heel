"""
Entitlement graph primitives.

The graph is a static import/model layer: it turns operator-authored ProductModel
metadata into typed entitlement edges and scenario-ready affordances. It performs no
live probing, executes no tools, and does not authorize anything. Imported targets still
require a human-created signed AuthorizationScope before any rehearsal run.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Mapping

from .contracts import Affordance, Category


class Principal(str, Enum):
    ANONYMOUS = "anonymous"
    USER = "user"
    ADMIN = "admin"
    OWNER = "owner"
    SERVICE_ACCOUNT = "service_account"
    INTEGRATION = "integration"
    AGENT = "agent"


class Scope(str, Enum):
    TENANT = "tenant"
    WORKSPACE = "workspace"
    ORG = "org"
    GLOBAL = "global"
    EXTERNAL_INTEGRATION = "external_integration"


class Resource(str, Enum):
    RECORD = "record"
    EXPORT = "export"
    BILLING_METER = "billing_meter"
    COUPON = "coupon"
    TRIAL = "trial"
    FEATURE = "feature"
    INVITE = "invite"
    WEBHOOK = "webhook"
    OAUTH_SCOPE = "oauth_scope"
    SUPPORT_ACTION = "support_action"
    AGENT_TOOL = "agent_tool"
    MCP_CONNECTOR = "mcp_connector"


class Control(str, Enum):
    ENTITLEMENT_CHECK = "entitlement_check"
    TENANT_FILTER = "tenant_filter"
    RATE_LIMIT = "rate_limit"
    QUOTA = "quota"
    AUDIT_LOG = "audit_log"
    APPROVAL = "approval"
    PROOF_OF_UNIQUENESS = "proof_of_uniqueness"
    PAYMENT_VERIFICATION = "payment_verification"
    SESSION_CONCURRENCY = "session_concurrency"
    HUMAN_REVIEW = "human_review"
    COST_CEILING = "cost_ceiling"


@dataclass(frozen=True)
class EntitlementEdge:
    id: str
    signal: str
    principal: Principal
    scope: Scope
    resource: Resource
    source_field: str
    source_id: str
    kind: str
    category: Category
    control: Control | None
    properties: dict[str, Any] = field(default_factory=dict)
    guard_present: bool = False
    reachability: float = 0.7


@dataclass(frozen=True)
class EntitlementGraph:
    product_id: str
    edges: tuple[EntitlementEdge, ...]

    @classmethod
    def from_product_model(cls, product_model: Mapping[str, Any] | Any) -> "EntitlementGraph":
        model = _as_mapping(product_model)
        builder = _GraphBuilder(model)
        return cls(product_id=builder.product_id, edges=tuple(sorted(builder.build(), key=lambda e: e.id)))

    def find_cross_plan_edges(self) -> list[EntitlementEdge]:
        return [e for e in self.edges if e.signal == "plan_mismatch"]

    def find_cross_tenant_edges(self) -> list[EntitlementEdge]:
        return [e for e in self.edges if e.signal in {"tenant_filter_missing", "tenant_filter_ambiguous"}]

    def find_unmetered_cost_edges(self) -> list[EntitlementEdge]:
        return [e for e in self.edges if e.signal == "unmetered_billable_resource"]

    def find_agent_overreach_edges(self) -> list[EntitlementEdge]:
        return [e for e in self.edges if e.signal in {"agent_tool_overscope", "mcp_connector_overscope"}]

    def find_missing_audit_edges(self) -> list[EntitlementEdge]:
        return [e for e in self.edges if e.signal == "missing_audit_event"]

    def to_affordances(self) -> list[Affordance]:
        affordances: list[Affordance] = []
        for edge in self.edges:
            props = dict(edge.properties)
            props.update({
                "entitlement_signal": edge.signal,
                "entitlement_principal": edge.principal.value,
                "entitlement_scope": edge.scope.value,
                "entitlement_resource": edge.resource.value,
                "source_field": edge.source_field,
                "source_id": edge.source_id,
            })
            if edge.control:
                props["control"] = edge.control.value
            affordances.append(Affordance(
                id=f"eg:{edge.kind}:{_safe_id(edge.source_id)}:{edge.signal}",
                kind=edge.kind,
                category=edge.category,
                properties=_ordered_dict(props),
                guard_present=edge.guard_present,
                reachability=edge.reachability,
                planted_weakness=None,
                true_severity=None,
                decoy=False,
            ))
        return affordances


class _GraphBuilder:
    def __init__(self, model: Mapping[str, Any]):
        self.model = model
        self.product_id = str(model.get("product_id") or "product")
        self.plan_rank = _plan_rank(model)
        self.audit_events = _audit_event_ids(model.get("audit_events", []))

    def build(self) -> list[EntitlementEdge]:
        edges: list[EntitlementEdge] = []
        self._add_plan_mismatches(edges)
        self._add_permission_mismatches(edges)
        self._add_export_entitlements(edges)
        self._add_tenant_filters(edges)
        self._add_unmetered_costs(edges)
        self._add_agent_overreach(edges)
        self._add_oauth_overreach(edges)
        self._add_missing_audits(edges)
        return edges

    def _add_plan_mismatches(self, edges: list[EntitlementEdge]) -> None:
        for field_name in ("features_flags", "endpoints_routes", "exports", "meters", "billing_objects", "coupons_promotions"):
            for idx, item in enumerate(_items(self.model, field_name)):
                props = _properties(item)
                required = _first_value(props, "required_plan", "entitlement_plan", "min_plan", "plan_required", "required_tier")
                reachable = _first_value(props, "reachable_by_plan", "granted_plan", "current_plan", "observed_plan")
                allowed = _to_list(_first_value(props, "allowed_plans", "entitled_plans"))
                if not _is_plan_mismatch(required, reachable, allowed, self.plan_rank):
                    continue
                sid = _source_id(item, idx)
                kind = _kind(field_name, props)
                edges.append(self._edge(
                    signal="plan_mismatch",
                    principal=Principal.USER,
                    scope=Scope.TENANT,
                    resource=_resource(field_name, kind),
                    source_field=field_name,
                    source_id=sid,
                    kind=kind,
                    category=Category.LICENSE_ENTITLEMENT,
                    control=Control.ENTITLEMENT_CHECK,
                    properties={
                        **props,
                        "required_plan": str(required or ""),
                        "reachable_by_plan": str(reachable or ""),
                    },
                    guard_present=False,
                    reachability=_reachability(props, 0.75),
                ))

    def _add_permission_mismatches(self, edges: list[EntitlementEdge]) -> None:
        for idx, item in enumerate(_items(self.model, "roles")):
            props = _properties(item)
            granted = set(_to_list(props.get("granted_permissions")))
            intended = set(_to_list(props.get("intended_permissions")))
            if not granted or not intended or not (granted - intended):
                continue
            sid = _source_id(item, idx)
            role = str(_first_value(props, "id", "role", "name") or sid)
            edges.append(self._edge(
                signal="permission_mismatch",
                principal=_principal(role),
                scope=Scope.TENANT,
                resource=_permission_resource(granted - intended),
                source_field="roles",
                source_id=sid,
                kind="role",
                category=Category.LICENSE_ENTITLEMENT,
                control=Control.ENTITLEMENT_CHECK,
                properties={
                    **props,
                    "granted_permissions": sorted(granted),
                    "intended_permissions": sorted(intended),
                    "extra_permissions": sorted(granted - intended),
                },
                guard_present=False,
                reachability=_reachability(props, 0.65),
            ))

        for field_name in ("support_admin_actions", "endpoints_routes"):
            for idx, item in enumerate(_items(self.model, field_name)):
                props = _properties(item)
                required = _first_value(props, "required_role", "min_role", "intended_role")
                reachable = _first_value(props, "reachable_by_role", "granted_role", "observed_role")
                if not _is_role_mismatch(required, reachable):
                    continue
                sid = _source_id(item, idx)
                kind = _kind(field_name, props)
                edges.append(self._edge(
                    signal="permission_mismatch",
                    principal=_principal(str(reachable or "")),
                    scope=Scope.TENANT,
                    resource=_resource(field_name, kind),
                    source_field=field_name,
                    source_id=sid,
                    kind=kind,
                    category=Category.LICENSE_ENTITLEMENT,
                    control=Control.ENTITLEMENT_CHECK,
                    properties={
                        **props,
                        "required_role": str(required or ""),
                        "reachable_by_role": str(reachable or ""),
                    },
                    guard_present=False,
                    reachability=_reachability(props, 0.65),
                ))

    def _add_export_entitlements(self, edges: list[EntitlementEdge]) -> None:
        for field_name in ("exports", "endpoints_routes"):
            for idx, item in enumerate(_items(self.model, field_name)):
                props = _properties(item)
                if field_name == "endpoints_routes" and "export" not in _text(props, "id", "name", "route", "path"):
                    continue
                entitlement = _first_value(props, "entitlement_check", "entitlement", "authz_check", "guard")
                if not (_bad_control(entitlement) or props.get("guard_present") is False or props.get("guard_absent") is True):
                    continue
                sid = _source_id(item, idx)
                edges.append(self._edge(
                    signal="export_without_entitlement",
                    principal=Principal.USER,
                    scope=Scope.TENANT,
                    resource=Resource.EXPORT,
                    source_field=field_name,
                    source_id=sid,
                    kind="export",
                    category=Category.DATA_HARVESTING,
                    control=Control.ENTITLEMENT_CHECK,
                    properties={
                        **props,
                        "entitlement_check": "missing",
                    },
                    guard_present=False,
                    reachability=_reachability(props, 0.8),
                ))

    def _add_tenant_filters(self, edges: list[EntitlementEdge]) -> None:
        for field_name in ("endpoints_routes", "exports", "agent_tools", "mcp_connectors"):
            for idx, item in enumerate(_items(self.model, field_name)):
                props = _properties(item)
                tenant_keys = ("tenant_filter", "tenant_check", "tenant_isolation", "workspace_filter")
                if not any(k in props for k in tenant_keys):
                    continue
                tenant_value = _first_value(props, *tenant_keys)
                if not (_bad_control(tenant_value) or str(tenant_value).strip().lower() == "ambiguous"):
                    continue
                sid = _source_id(item, idx)
                kind = _kind(field_name, props)
                if kind == "endpoint" and "record" in _text(props, "id", "name", "route", "path"):
                    kind = "record"
                signal = "tenant_filter_ambiguous" if str(tenant_value).strip().lower() == "ambiguous" else "tenant_filter_missing"
                edges.append(self._edge(
                    signal=signal,
                    principal=Principal.AGENT if field_name in {"agent_tools", "mcp_connectors"} else Principal.USER,
                    scope=Scope.TENANT,
                    resource=_resource(field_name, kind),
                    source_field=field_name,
                    source_id=sid,
                    kind=kind,
                    category=Category.COMPLIANCE_BOUNDARY if kind != "agent_tool" else Category.AGENT_MCP_SURFACE,
                    control=Control.TENANT_FILTER,
                    properties={
                        **props,
                        "tenant_filter": "missing" if signal == "tenant_filter_missing" else "ambiguous",
                        "tenant_check": "missing" if signal == "tenant_filter_missing" else "ambiguous",
                    },
                    guard_present=False,
                    reachability=_reachability(props, 0.75),
                ))

    def _add_unmetered_costs(self, edges: list[EntitlementEdge]) -> None:
        for field_name in ("meters", "billing_objects", "agent_tools"):
            for idx, item in enumerate(_items(self.model, field_name)):
                props = _properties(item)
                billable = _truthy(_first_value(props, "billable", "cost_bearing", "metered", "charges_money"))
                accounting = _first_value(props, "server_side_accounting", "server_authoritative", "meter_accounting", "cost_accounting")
                cost_ceiling = _first_value(props, "cost_ceiling", "quota", "spend_limit")
                if not billable or not (_bad_control(accounting) or _bad_control(cost_ceiling)):
                    continue
                sid = _source_id(item, idx)
                kind = _kind(field_name, props)
                edges.append(self._edge(
                    signal="unmetered_billable_resource",
                    principal=Principal.AGENT if kind == "agent_tool" else Principal.USER,
                    scope=Scope.TENANT,
                    resource=Resource.AGENT_TOOL if kind == "agent_tool" else Resource.BILLING_METER,
                    source_field=field_name,
                    source_id=sid,
                    kind=kind,
                    category=Category.AGENT_MCP_SURFACE if kind == "agent_tool" else Category.LICENSE_ENTITLEMENT,
                    control=Control.COST_CEILING if kind == "agent_tool" else Control.QUOTA,
                    properties={
                        **props,
                        "server_side_accounting": False if _bad_control(accounting) else accounting,
                        "cost_ceiling": "missing" if _bad_control(cost_ceiling) else cost_ceiling,
                    },
                    guard_present=False,
                    reachability=_reachability(props, 0.65),
                ))

    def _add_agent_overreach(self, edges: list[EntitlementEdge]) -> None:
        for field_name, signal in (("agent_tools", "agent_tool_overscope"), ("mcp_connectors", "mcp_connector_overscope")):
            for idx, item in enumerate(_items(self.model, field_name)):
                props = _properties(item)
                granted = _first_value(props, "granted_scope", "effective_scope", "scope")
                intended = _first_value(props, "intended_scope", "required_scope", "declared_scope")
                if granted is None or intended is None or str(granted) == str(intended):
                    continue
                sid = _source_id(item, idx)
                kind = _kind(field_name, props)
                edges.append(self._edge(
                    signal=signal,
                    principal=Principal.AGENT,
                    scope=_scope(str(granted)),
                    resource=Resource.AGENT_TOOL if kind == "agent_tool" else Resource.MCP_CONNECTOR,
                    source_field=field_name,
                    source_id=sid,
                    kind=kind,
                    category=Category.AGENT_MCP_SURFACE,
                    control=Control.ENTITLEMENT_CHECK,
                    properties={
                        **props,
                        "granted_scope": str(granted),
                        "intended_scope": str(intended),
                    },
                    guard_present=False,
                    reachability=_reachability(props, 0.8),
                ))

    def _add_oauth_overreach(self, edges: list[EntitlementEdge]) -> None:
        for idx, item in enumerate(_items(self.model, "integration_oauth_apps")):
            props = _properties(item)
            scope_value = _first_value(props, "scope", "granted_scope", "oauth_scope")
            granted = set(_to_list(_first_value(props, "granted_scopes", "scopes")))
            needed = set(_to_list(_first_value(props, "needed_scopes", "required_scopes", "intended_scopes")))
            scope_all = str(scope_value).strip().lower() in {"all", "*", "admin", "full_access", "read_write_all"}
            excess = granted and needed and not granted.issubset(needed)
            if not (scope_all or excess):
                continue
            sid = _source_id(item, idx)
            edges.append(self._edge(
                signal="oauth_scope_overbroad",
                principal=Principal.INTEGRATION,
                scope=Scope.EXTERNAL_INTEGRATION,
                resource=Resource.OAUTH_SCOPE,
                source_field="integration_oauth_apps",
                source_id=sid,
                kind="oauth_app",
                category=Category.INTEGRATION_EXTENSIBILITY,
                control=Control.APPROVAL,
                properties={
                    **props,
                    "scope": "all" if scope_all else ",".join(sorted(granted)),
                    "needed_scopes": sorted(needed),
                },
                guard_present=False,
                reachability=_reachability(props, 0.65),
            ))

    def _add_missing_audits(self, edges: list[EntitlementEdge]) -> None:
        for idx, item in enumerate(_items(self.model, "support_admin_actions")):
            props = _properties(item)
            audit_logged = props.get("audit_logged")
            audit_event = _first_value(props, "audit_event", "audit_event_id", "event")
            has_event = bool(audit_event) and str(audit_event) in self.audit_events
            missing = False if _truthy(audit_logged) or has_event else (
                _bad_control(audit_logged) or _bad_control(audit_event) or (audit_event is not None and not has_event)
            )
            if not missing:
                continue
            sid = _source_id(item, idx)
            edges.append(self._edge(
                signal="missing_audit_event",
                principal=Principal.ADMIN,
                scope=Scope.TENANT,
                resource=Resource.SUPPORT_ACTION,
                source_field="support_admin_actions",
                source_id=sid,
                kind="admin_action",
                category=Category.COMPLIANCE_BOUNDARY,
                control=Control.AUDIT_LOG,
                properties={
                    **props,
                    "audit_logged": False,
                },
                guard_present=False,
                reachability=_reachability(props, 0.65),
            ))

    def _edge(self, *, signal: str, principal: Principal, scope: Scope, resource: Resource,
              source_field: str, source_id: str, kind: str, category: Category,
              control: Control | None, properties: dict[str, Any],
              guard_present: bool, reachability: float) -> EntitlementEdge:
        eid = f"edge:{_safe_id(source_field)}:{_safe_id(source_id)}:{signal}"
        return EntitlementEdge(
            id=eid,
            signal=signal,
            principal=principal,
            scope=scope,
            resource=resource,
            source_field=source_field,
            source_id=source_id,
            kind=kind,
            category=category,
            control=control,
            properties=_ordered_dict(properties),
            guard_present=guard_present,
            reachability=reachability,
        )


def _as_mapping(product_model: Mapping[str, Any] | Any) -> Mapping[str, Any]:
    if isinstance(product_model, Mapping):
        return product_model
    raw = getattr(product_model, "raw", None)
    if isinstance(raw, Mapping):
        return raw
    out = {}
    for name in (
        "product_id", "tenants", "roles", "plans", "meters", "coupons_promotions",
        "features_flags", "endpoints_routes", "exports", "billing_objects",
        "integration_oauth_apps", "webhooks", "support_admin_actions", "agent_tools",
        "mcp_connectors", "audit_events",
    ):
        if hasattr(product_model, name):
            out[name] = getattr(product_model, name)
    return out


def _items(model: Mapping[str, Any], field_name: str) -> list[Any]:
    value = model.get(field_name, [])
    return value if isinstance(value, list) else []


def _properties(item: Any) -> dict[str, Any]:
    if isinstance(item, Mapping):
        return {str(k): v for k, v in item.items()}
    return {"name": str(item)}


def _first_value(props: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in props:
            return props[name]
    return None


def _to_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    if isinstance(value, str) and "," in value:
        return [v.strip() for v in value.split(",") if v.strip()]
    return [str(value)]


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, (int, float)) and value:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "on", "billable", "metered", "paid", "enabled"}
    return False


def _bad_control(value: Any) -> bool:
    if value is False or value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {
            "", "missing", "none", "false", "disabled", "off", "no", "weak",
            "client", "client_only", "ambiguous", "unknown",
        }
    return False


def _plan_rank(model: Mapping[str, Any]) -> dict[str, int]:
    fallback = {
        "free": 0, "starter": 1, "basic": 1, "trial": 1, "pro": 2, "team": 2,
        "business": 3, "enterprise": 4,
    }
    plans = _items(model, "plans")
    if not plans:
        return fallback
    ranked = dict(fallback)
    for idx, plan in enumerate(plans):
        props = _properties(plan)
        name = str(_first_value(props, "id", "name", "plan") or idx).strip().lower()
        ranked[name] = idx
    return ranked


def _is_plan_mismatch(required: Any, reachable: Any, allowed: list[str], ranks: Mapping[str, int]) -> bool:
    if allowed and reachable is not None:
        return str(reachable).strip().lower() not in {a.strip().lower() for a in allowed}
    if required is None or reachable is None:
        return False
    req = str(required).strip().lower()
    got = str(reachable).strip().lower()
    if req == got:
        return False
    return ranks.get(got, -1) < ranks.get(req, 999) or got not in ranks


_ROLE_RANK = {
    "anonymous": 0,
    "guest": 0,
    "user": 1,
    "member": 1,
    "service_account": 1,
    "integration": 1,
    "admin": 2,
    "owner": 3,
}


def _is_role_mismatch(required: Any, reachable: Any) -> bool:
    if required is None or reachable is None:
        return False
    req = str(required).strip().lower()
    got = str(reachable).strip().lower()
    return got != req and _ROLE_RANK.get(got, -1) < _ROLE_RANK.get(req, 999)


def _principal(role: str) -> Principal:
    role = role.strip().lower()
    if role == "anonymous":
        return Principal.ANONYMOUS
    if role == "admin":
        return Principal.ADMIN
    if role == "owner":
        return Principal.OWNER
    if role == "service_account":
        return Principal.SERVICE_ACCOUNT
    if role == "integration":
        return Principal.INTEGRATION
    if role == "agent":
        return Principal.AGENT
    return Principal.USER


def _scope(value: str) -> Scope:
    v = value.strip().lower()
    if v == "global" or v == "all_tenants":
        return Scope.GLOBAL
    if v == "org":
        return Scope.ORG
    if v == "workspace":
        return Scope.WORKSPACE
    if "integration" in v:
        return Scope.EXTERNAL_INTEGRATION
    return Scope.TENANT


def _kind(field_name: str, props: Mapping[str, Any]) -> str:
    explicit = props.get("kind")
    if isinstance(explicit, str) and explicit:
        return explicit
    if field_name == "features_flags":
        return "flag"
    if field_name == "endpoints_routes":
        return "endpoint"
    if field_name == "exports":
        return "export"
    if field_name == "meters":
        return "meter"
    if field_name == "billing_objects":
        return "billing"
    if field_name == "coupons_promotions":
        return "promotion"
    if field_name == "integration_oauth_apps":
        return "oauth_app"
    if field_name == "support_admin_actions":
        return "admin_action"
    if field_name == "agent_tools":
        return "agent_tool"
    if field_name == "mcp_connectors":
        return "mcp_connector"
    return field_name.rstrip("s")


def _resource(field_name: str, kind: str) -> Resource:
    if kind == "record":
        return Resource.RECORD
    if kind == "export":
        return Resource.EXPORT
    if kind == "meter":
        return Resource.BILLING_METER
    if kind == "promotion":
        return Resource.COUPON
    if kind == "trial":
        return Resource.TRIAL
    if kind == "flag":
        return Resource.FEATURE
    if kind == "admin_action":
        return Resource.SUPPORT_ACTION
    if kind == "agent_tool":
        return Resource.AGENT_TOOL
    if kind == "mcp_connector":
        return Resource.MCP_CONNECTOR
    if field_name == "webhooks":
        return Resource.WEBHOOK
    return Resource.FEATURE


def _permission_resource(perms: set[str]) -> Resource:
    text = " ".join(perms).lower()
    if "invite" in text:
        return Resource.INVITE
    if "support" in text or "admin" in text:
        return Resource.SUPPORT_ACTION
    if "export" in text:
        return Resource.EXPORT
    return Resource.FEATURE


def _audit_event_ids(items: Any) -> set[str]:
    ids = set()
    for idx, item in enumerate(items if isinstance(items, list) else []):
        props = _properties(item)
        ids.add(str(_first_value(props, "id", "event", "name") or idx))
    return ids


def _source_id(item: Any, idx: int) -> str:
    props = _properties(item)
    for key in ("id", "name", "route", "path", "tool", "connector", "role", "plan", "event", "action"):
        if props.get(key):
            return _safe_id(str(props[key]))
    return str(idx)


def _text(props: Mapping[str, Any], *keys: str) -> str:
    return " ".join(str(props.get(k, "")) for k in keys).lower()


def _reachability(props: Mapping[str, Any], default: float) -> float:
    value = props.get("reachability")
    if isinstance(value, (int, float)):
        return round(max(0.05, min(0.95, float(value))), 3)
    return default


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "_", value.strip())
    cleaned = cleaned.strip("_")
    return cleaned[:80] or "item"


def _ordered_dict(values: Mapping[str, Any]) -> dict[str, Any]:
    return {k: values[k] for k in sorted(values)}
