"""Access-control and overposting source leads.

These rules catch high-value bounty shapes the pure sink packs miss: object
lookups keyed directly by request-controlled IDs, and model updates/creates that
accept an entire request body. They are intentionally labelled as leads, not
confirmed vulnerabilities; the report pipeline maps them to access-control and
requires role/two-account proof before a bounty submission is treated as ready.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

RULES = (
    RegexRule(
        rule_id="py.django-object-by-request-id",
        title="Django object lookup keyed by request-controlled id",
        description=(
            "A Django model lookup uses request.GET/POST/data/query_params as the object id. "
            "If the query is not scoped to the authenticated owner/tenant, this is an IDOR/BOLA lead."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        category="access_control",
        remediation=(
            "Scope object queries by the authenticated principal or tenant, for example "
            "Model.objects.get(id=obj_id, owner=request.user), then enforce object-level permissions."
        ),
        languages=("python",),
        pattern=(
            r"\b[A-Za-z_]\w*\.objects\.(?:get|filter)\s*\([^)]*(?:id|pk)\s*=\s*"
            r"request\.(?:GET|POST|data|query_params)\s*(?:\.get\s*\(|\[)"
        ),
        flags=re.MULTILINE,
        line_must_not_contain=("request.user", "current_user", "owner=", "tenant=", "organization="),
    ),
    RegexRule(
        rule_id="py.sqlalchemy-query-request-id",
        title="SQLAlchemy object lookup keyed by request-controlled id",
        description=(
            "A Flask/SQLAlchemy query reads an object by an id taken straight from request args/form/json. "
            "Without a same-query owner/tenant predicate, this is an IDOR/BOLA lead."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        category="access_control",
        remediation=(
            "Require an authorization predicate in the same lookup, e.g. filter_by(id=obj_id, "
            "owner_id=current_user.id), and return 404/403 for unauthorized objects."
        ),
        languages=("python",),
        pattern=(
            r"\b[A-Za-z_]\w*\.query\.(?:get|get_or_404)\s*\(\s*"
            r"request\.(?:args|form|values|json)\s*(?:\.get\s*\(|\[)"
            r"|\b[A-Za-z_]\w*\.query\.filter_by\s*\([^)]*(?:id|pk)\s*=\s*"
            r"request\.(?:args|form|values|json)\s*(?:\.get\s*\(|\[)"
        ),
        flags=re.MULTILINE,
        line_must_not_contain=("current_user", "g.user", "owner_id", "tenant_id", "org_id"),
    ),
    RegexRule(
        rule_id="js.mongoose-object-by-request-id",
        title="Mongoose/ORM object lookup keyed by request-controlled id",
        description=(
            "A Node handler queries an object by req.params/query/body id. If the query is not scoped "
            "to req.user or a tenant, this is a BOLA/IDOR lead."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        category="access_control",
        remediation=(
            "Include the authenticated owner/tenant in the lookup, e.g. findOne({_id: id, owner: req.user.id}), "
            "and enforce object-level authorization before returning data or mutating state."
        ),
        languages=("javascript", "typescript"),
        pattern=(
            r"\.\s*(?:findById|findOne|findByIdAndUpdate|findOneAndUpdate)\s*\(\s*"
            r"(?:req\.(?:params|query|body)\.[A-Za-z_$][\w$]*|\{[^}\n]*(?:_?id|slug)\s*:\s*"
            r"req\.(?:params|query|body)\.)"
        ),
        flags=re.MULTILINE,
        line_must_not_contain=("req.user", "currentUser", "owner", "tenant", "organizationId"),
    ),
    RegexRule(
        rule_id="js.request-body-mass-assignment",
        title="Request body passed directly into model create/update",
        description=(
            "A Node handler passes req.body wholesale into a model constructor/create/update call. "
            "That can let users overpost privileged fields such as role, owner_id, billing state, or feature flags."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        category="access_control",
        remediation=(
            "Build an explicit allowlist of writable fields before creating/updating models; never trust "
            "req.body as the whole persistence object."
        ),
        languages=("javascript", "typescript"),
        pattern=(
            r"\b(?:Object\.assign\s*\([^,\n]+,\s*req\.body|new\s+[A-Z][A-Za-z0-9_$]*\s*\(\s*req\.body\s*\)"
            r"|[A-Za-z_$][\w$]*\s*\.\s*(?:create|update|updateOne|findByIdAndUpdate|findOneAndUpdate)"
            r"\s*\([^;\n]*req\.body)"
        ),
        flags=re.MULTILINE,
        line_must_not_contain=("pick(", "omit(", "allowlist", "whitelist", "permitted", "sanitize"),
    ),
    RegexRule(
        rule_id="py.drf-modelserializer-all-fields",
        title="DRF ModelSerializer exposes all model fields",
        description=(
            "A Django REST Framework ModelSerializer uses fields='__all__'. If this serializer is writable, "
            "clients may overpost privileged model fields unless object permissions and read_only_fields are strict."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        category="access_control",
        remediation=(
            "Replace fields='__all__' with an explicit field list and mark server-controlled fields read-only."
        ),
        languages=("python",),
        pattern=r"\bfields\s*=\s*[\"']__all__[\"']",
        flags=re.MULTILINE,
    ),
)
