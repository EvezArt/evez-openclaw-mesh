"""EVEZ distributed tool registry reference API.

Read-only by default. Single-process starter; production needs a durable registry,
authenticated peer identity, egress enforcement, and a tamper-evident audit sink.
"""
from __future__ import annotations
import hashlib, hmac, ipaddress, json, os, secrets, socket, threading, time, urllib.parse
from collections import OrderedDict, defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
import httpx
import rfc8785
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field

READONLY = os.getenv("EVEZ_TOOLS_READONLY", "1").lower() in {"1", "true", "yes", "on"}
ADMIN_TOKEN = os.getenv("EVEZ_ADMIN_TOKEN", "")
AGENT_TOKEN = os.getenv("EVEZ_AGENT_TOKEN", "")
AUDIT_PATH = Path(os.getenv("EVEZ_AUDIT_PATH", "logs/audit.jsonl"))
ALLOWED_HOSTS = {v.strip().lower().rstrip(".") for v in os.getenv("EVEZ_TOOL_ALLOWED_HOSTS", "").split(",") if v.strip()}
HERMES_POLICY_URL = os.getenv("EVEZ_HERMES_POLICY_URL", "").strip()
HERMES_POLICY_TOKEN = os.getenv("EVEZ_HERMES_POLICY_TOKEN", "")
MAX_REQUEST_BYTES = int(os.getenv("EVEZ_MAX_REQUEST_BYTES", "262144"))
MAX_RESPONSE_BYTES = int(os.getenv("EVEZ_MAX_RESPONSE_BYTES", "1048576"))
IDEMPOTENCY_TTL_SECONDS = 900
IDEMPOTENCY_MAX_ENTRIES = 1000
HIGH_RISK_PREFIXES = ("shell.", "docker.", "k8s.", "deploy.", "credential.", "secret.", "payment.", "file.write", "file.delete", "git.push", "git.merge", "system.admin", "permission.change")
try:
    TRUSTED_MESH_CIDRS = tuple(ipaddress.ip_network(v.strip(), strict=False) for v in os.getenv("EVEZ_MESH_CIDRS", "").split(",") if v.strip())
    raw_creds = json.loads(os.getenv("EVEZ_AGENT_CREDENTIALS_JSON", "{}"))
    AGENT_CREDENTIALS = {str(k): {"token": str(v["token"]), "capabilities": set(v.get("capabilities", []))} for k, v in raw_creds.items() if isinstance(v, dict) and isinstance(v.get("token"), str) and v.get("token") and isinstance(v.get("capabilities", []), list)}
    raw_grants = json.loads(os.getenv("EVEZ_AGENT_GRANTS_JSON", "{}"))
    AGENT_GRANTS = {str(k): set(v) for k, v in raw_grants.items() if isinstance(v, list)}
except (ValueError, TypeError, KeyError, AttributeError) as exc:
    raise RuntimeError("Invalid EVEZ agent grant or mesh CIDR configuration") from exc
REGISTRY: dict[str, dict[str, Any]] = {}
RATE_EVENTS: dict[str, deque[float]] = defaultdict(deque)
IDEMPOTENCY: OrderedDict[tuple[str, str, str], tuple[float, str, dict[str, Any]]] = OrderedDict()
AUDIT_LOCK = threading.RLock()
REGISTRY_LOCK = threading.RLock()
AUDIT_CACHE: tuple[str, int, int, str] | None = None
app = FastAPI(title="EVEZ Distributed Tool Registry", version="1.2.0")

class Service(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["http", "grpc"]
    endpoint: str = Field(min_length=8, max_length=2048)

class RateLimit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requests_per_minute: int = Field(default=60, ge=1, le=10000)

class AuthPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    required: bool = True
    roles: list[Literal["agent", "admin"]] = Field(default_factory=lambda: ["agent", "admin"], min_length=1)

class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
    description: str = Field(min_length=1, max_length=500)
    service: Service
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    capabilities: list[str] = Field(min_length=1, max_length=64)
    rate_limit: RateLimit = Field(default_factory=RateLimit)
    auth: AuthPolicy = Field(default_factory=AuthPolicy)
    enabled: bool = True

class Invocation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    params: dict[str, Any]
    capability: str | None = Field(default=None, min_length=1, max_length=128)
    timeout_seconds: int = Field(default=20, ge=1, le=120)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)
    approval_id: str | None = Field(default=None, min_length=1, max_length=200)

def digest(value: Any) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()

def verify_audit_chain() -> str:
    global AUDIT_CACHE
    try:
        if not AUDIT_PATH.exists():
            AUDIT_CACHE = (str(AUDIT_PATH), 0, 0, "GENESIS")
            return "GENESIS"
        stat = AUDIT_PATH.stat()
        if AUDIT_CACHE and AUDIT_CACHE[:3] == (str(AUDIT_PATH), stat.st_size, stat.st_mtime_ns):
            return AUDIT_CACHE[3]
        prior = "GENESIS"
        for line_no, line in enumerate(AUDIT_PATH.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            supplied = record.pop("event_hash", None)
            if record.get("previous_hash") != prior or not isinstance(supplied, str) or not hmac.compare_digest(digest(record), supplied):
                raise ValueError(f"invalid audit chain at line {line_no}")
            prior = supplied
        stat = AUDIT_PATH.stat()
        AUDIT_CACHE = (str(AUDIT_PATH), stat.st_size, stat.st_mtime_ns, prior)
        return prior
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail="Audit chain invalid or unreadable; request blocked") from exc

def audit(event: dict[str, Any]) -> None:
    global AUDIT_CACHE
    with AUDIT_LOCK:
        prior = verify_audit_chain()
        record = {"timestamp": datetime.now(timezone.utc).isoformat(), **event, "previous_hash": prior}
        record["event_hash"] = digest(record)
        try:
            AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(AUDIT_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as out:
                os.fchmod(out.fileno(), 0o600)
                out.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
                out.flush()
                os.fsync(out.fileno())
            stat = AUDIT_PATH.stat()
            AUDIT_CACHE = (str(AUDIT_PATH), stat.st_size, stat.st_mtime_ns, record["event_hash"])
        except OSError as exc:
            raise HTTPException(status_code=503, detail="Audit sink unavailable; request not performed") from exc

def caller(x_evez_token: str | None = Header(default=None),
           x_evez_role: str | None = Header(default=None)) -> dict[str, str]:
    if not x_evez_token or not x_evez_role:
        raise HTTPException(status_code=401, detail="Missing EVEZ credentials")
    if x_evez_role == "admin" and ADMIN_TOKEN and hmac.compare_digest(x_evez_token, ADMIN_TOKEN):
        return {"role": "admin", "identity": "admin-token"}
    if x_evez_role == "agent":
        for identity, entry in AGENT_CREDENTIALS.items():
            if hmac.compare_digest(x_evez_token, entry["token"]):
                return {"role": "agent", "identity": identity}
        if AGENT_TOKEN and hmac.compare_digest(x_evez_token, AGENT_TOKEN):
            return {"role": "agent", "identity": "agent-token"}
    raise HTTPException(status_code=403, detail="Invalid credentials or role")

def granted_capabilities(who: dict[str, str]) -> set[str]:
    if who["identity"] in AGENT_CREDENTIALS:
        return set(AGENT_CREDENTIALS[who["identity"]]["capabilities"])
    return set(AGENT_GRANTS.get(who["identity"], set()))

def admin(who: dict[str, str] = Depends(caller)) -> dict[str, str]:
    if who["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return who

def endpoint_ok(raw: str, kind: str) -> str:
    parsed = urllib.parse.urlsplit(raw)
    allowed = {"http": {"https"}, "grpc": {"grpcs"}}[kind]
    if parsed.scheme.lower() not in allowed or not parsed.hostname:
        raise HTTPException(status_code=422, detail="Remote endpoints require HTTPS or secure gRPC")
    if parsed.username or parsed.password or parsed.fragment:
        raise HTTPException(status_code=422, detail="Endpoint credentials/fragments are forbidden")
    host = parsed.hostname.lower().rstrip(".")
    if not ALLOWED_HOSTS or host not in ALLOWED_HOSTS:
        raise HTTPException(status_code=422, detail="Endpoint hostname is not in EVEZ_TOOL_ALLOWED_HOSTS")
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 50051)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid endpoint port") from exc
    try:
        try:
            addresses = {ipaddress.ip_address(host)}
        except ValueError:
            addresses = {ipaddress.ip_address(row[4][0].split("%", 1)[0]) for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Endpoint did not resolve to valid IP addresses") from exc
    if not addresses:
        raise HTTPException(status_code=422, detail="Endpoint has no addresses")
    def allowed_ip(address):
        if address.is_global:
            return True
        return host.endswith(".evez.mesh") and any(address.version == cidr.version and address in cidr for cidr in TRUSTED_MESH_CIDRS)
    if any(not allowed_ip(address) for address in addresses):
        raise HTTPException(status_code=422, detail="Endpoint resolves to private/reserved address outside trusted mesh CIDRs")
    return raw

def is_high_risk(capability: str) -> bool:
    return any(capability == prefix or capability.startswith(prefix) for prefix in HIGH_RISK_PREFIXES)

async def hermes_approve(request_id: str, who: dict[str, str], item: dict[str, Any], capability: str, body: Invocation) -> None:
    if not HERMES_POLICY_URL or not HERMES_POLICY_TOKEN or not body.approval_id:
        raise HTTPException(status_code=423, detail="High-risk capability blocked: Hermes approval adapter and approval_id are required")
    endpoint_ok(HERMES_POLICY_URL, "http")
    params_hash = digest(body.params)
    payload = {"request_id": request_id, "actor": who["identity"], "role": who["role"], "tool": item["name"], "manifest_digest": item["manifest_digest"], "capability": capability, "params_sha256": params_hash, "approval_id": body.approval_id}
    try:
        async with httpx.AsyncClient(timeout=3.0, follow_redirects=False, trust_env=False) as client:
            response = await client.post(HERMES_POLICY_URL, json=payload, headers={"Authorization": f"Bearer {HERMES_POLICY_TOKEN}"})
        if response.status_code != 200:
            raise HTTPException(status_code=423, detail="Hermes policy adapter did not authorize request")
        result = response.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail="Hermes policy adapter unavailable; request blocked") from exc
    expected = {"decision": "allow", "approval_id": body.approval_id, "request_id": request_id, "tool": item["name"], "capability": capability, "manifest_digest": item["manifest_digest"], "params_sha256": params_hash}
    if not isinstance(result, dict) or any(result.get(key) != value for key, value in expected.items()):
        raise HTTPException(status_code=403, detail="Hermes approval did not bind to exact caller/action/input")

def cached_result(identity: str, tool: str, key: str | None, param_hash: str) -> dict[str, Any] | None:
    if not key:
        return None
    now = time.monotonic()
    for cache_key, (created, _, _) in list(IDEMPOTENCY.items()):
        if now - created > IDEMPOTENCY_TTL_SECONDS:
            IDEMPOTENCY.pop(cache_key, None)
    cache_key = (identity, tool, key)
    saved = IDEMPOTENCY.get(cache_key)
    if not saved:
        return None
    _, old_hash, result = saved
    if not hmac.compare_digest(old_hash, param_hash):
        raise HTTPException(status_code=409, detail="Idempotency key reused with different parameters")
    IDEMPOTENCY.move_to_end(cache_key)
    return {**result, "idempotent_replay": True}

def save_result(identity: str, tool: str, key: str | None, param_hash: str, result: dict[str, Any]) -> None:
    if not key:
        return
    cache_key = (identity, tool, key)
    IDEMPOTENCY[cache_key] = (time.monotonic(), param_hash, result)
    IDEMPOTENCY.move_to_end(cache_key)
    while len(IDEMPOTENCY) > IDEMPOTENCY_MAX_ENTRIES:
        IDEMPOTENCY.popitem(last=False)

def schema_ok(m: Manifest) -> None:
    try:
        Draft202012Validator.check_schema(m.input_schema)
        Draft202012Validator.check_schema(m.output_schema)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON Schema: {type(exc).__name__}") from exc

def throttled(name: str, limit: int) -> None:
    now = time.monotonic()
    queue = RATE_EVENTS[name]
    while queue and now - queue[0] >= 60:
        queue.popleft()
    if len(queue) >= limit:
        raise HTTPException(status_code=429, detail="Tool rate limit exceeded")
    queue.append(now)

def public(item: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in item.items() if k not in {"manifest_digest", "registered_by"}}

@app.get("/health")
def health() -> dict[str, Any]:
    head = verify_audit_chain()
    return {"status": "healthy", "version": "1.2.0", "readonly": READONLY, "registered_tools": len(REGISTRY), "audit_chain_valid": True, "audit_head": head, "canonicalization": "RFC8785-JCS"}

@app.get("/tools")
def list_tools(capability: str | None = None, who: dict[str, str] = Depends(caller)) -> dict[str, Any]:
    tools = [public(v) for v in REGISTRY.values() if v["enabled"] and (not capability or capability in v["capabilities"])]
    return {"tools": tools, "count": len(tools)}

@app.get("/tools/capabilities/{capability:path}")
def discover(capability: str, who: dict[str, str] = Depends(caller)) -> dict[str, Any]:
    tools = [public(v) for v in REGISTRY.values() if v["enabled"] and capability in v["capabilities"]]
    return {"capability": capability, "tools": tools, "count": len(tools)}

@app.get("/tools/{name}/health")
def tool_health(name: str, who: dict[str, str] = Depends(caller)) -> dict[str, Any]:
    item = REGISTRY.get(name)
    if item is None:
        raise HTTPException(status_code=404, detail="Unknown tool")
    return {"name": name, "status": "registered" if item["enabled"] else "disabled", "version": item["version"]}

@app.get("/tools/{name}")
def tool_details(name: str, who: dict[str, str] = Depends(caller)) -> dict[str, Any]:
    item = REGISTRY.get(name)
    if item is None:
        raise HTTPException(status_code=404, detail="Unknown tool")
    return public(item)

@app.post("/tools/register", status_code=201)
def register(manifest: Manifest, who: dict[str, str] = Depends(admin)) -> dict[str, Any]:
    if READONLY:
        raise HTTPException(status_code=423, detail="EVEZ_TOOLS_READONLY is enabled")
    endpoint_ok(manifest.service.endpoint, manifest.service.type)
    schema_ok(manifest)
    payload = manifest.model_dump(mode="json")
    version_digest = digest(payload)
    record = {**payload, "manifest_digest": version_digest, "registered_by": who["identity"]}
    with REGISTRY_LOCK:
        old = REGISTRY.get(manifest.name)
        if old and old["version"] == manifest.version and old["manifest_digest"] != version_digest:
            raise HTTPException(status_code=409, detail="Same name/version cannot change content")
        audit({"event": "tool.register.requested", "actor": who["identity"], "tool": manifest.name, "version": manifest.version, "manifest_digest": version_digest})
        REGISTRY[manifest.name] = record
        audit({"event": "tool.registered", "actor": who["identity"], "tool": manifest.name, "version": manifest.version, "manifest_digest": version_digest})
    return {"registered": True, "tool": public(record), "manifest_digest": version_digest}

@app.delete("/tools/{name}")
def unregister(name: str, who: dict[str, str] = Depends(admin)) -> dict[str, Any]:
    if READONLY:
        raise HTTPException(status_code=423, detail="EVEZ_TOOLS_READONLY is enabled")
    with REGISTRY_LOCK:
        item = REGISTRY.get(name)
        if item is None:
            raise HTTPException(status_code=404, detail="Unknown tool")
        audit({"event": "tool.unregister.requested", "actor": who["identity"], "tool": name, "version": item["version"], "manifest_digest": item["manifest_digest"]})
        item["enabled"] = False
        audit({"event": "tool.unregistered", "actor": who["identity"], "tool": name, "version": item["version"], "manifest_digest": item["manifest_digest"]})
    return {"unregistered": True, "name": name, "status": "disabled"}

@app.post("/tools/{name}/invoke")
async def invoke(name: str, request: Invocation, who: dict[str, str] = Depends(caller)) -> dict[str, Any]:
    request_id = secrets.token_hex(12)
    item = REGISTRY.get(name)
    if item is None or not item["enabled"]:
        audit({"event": "tool.invoke.denied", "request_id": request_id, "actor": who["identity"], "tool": name, "reason": "unknown_or_disabled"})
        raise HTTPException(status_code=404, detail="Tool unavailable")
    if who["role"] not in item["auth"]["roles"]:
        raise HTTPException(status_code=403, detail="Caller role is not allowed")
    if READONLY:
        audit({"event": "tool.invoke.denied", "request_id": request_id, "actor": who["identity"], "tool": name, "reason": "readonly"})
        raise HTTPException(status_code=423, detail="EVEZ_TOOLS_READONLY blocks invocation")
    errors = list(Draft202012Validator(item["input_schema"]).iter_errors(request.params))
    if errors:
        raise HTTPException(status_code=422, detail={"message": "Input schema validation failed", "errors": [e.message for e in errors[:10]]})
    capability = request.capability
    if capability is None:
        if len(item["capabilities"]) != 1:
            raise HTTPException(status_code=422, detail="Specify capability for tools declaring multiple capabilities")
        capability = item["capabilities"][0]
    if capability not in item["capabilities"]:
        audit({"event": "tool.invoke.denied", "request_id": request_id, "actor": who["identity"], "tool": name, "capability": capability, "reason": "capability_not_declared"})
        raise HTTPException(status_code=403, detail="Capability is not declared by the tool")
    if who["role"] != "admin" and capability not in granted_capabilities(who):
        audit({"event": "tool.invoke.denied", "request_id": request_id, "actor": who["identity"], "tool": name, "capability": capability, "reason": "capability_not_granted"})
        raise HTTPException(status_code=403, detail="Agent is not granted this capability")
    if is_high_risk(capability):
        try:
            await hermes_approve(request_id, who, item, capability, request)
        except HTTPException as exc:
            audit({"event": "tool.invoke.denied", "request_id": request_id, "actor": who["identity"], "tool": name, "capability": capability, "reason": "hermes_policy_denied", "status_code": exc.status_code})
            raise
        audit({"event": "tool.invoke.approved", "request_id": request_id, "actor": who["identity"], "tool": name, "capability": capability, "approval_id": request.approval_id})
    params_hash = digest(request.params)
    replay = cached_result(who["identity"], name, request.idempotency_key, params_hash)
    if replay is not None:
        audit({"event": "tool.invoke.idempotent_replay", "request_id": request_id, "actor": who["identity"], "tool": name, "capability": capability})
        return replay
    throttled(f"{who['identity']}:{name}", item["rate_limit"]["requests_per_minute"])
    target = endpoint_ok(item["service"]["endpoint"], item["service"]["type"])
    if item["service"]["type"] != "http":
        raise HTTPException(status_code=501, detail="gRPC adapter not installed")
    audit({"event": "tool.invoke.started", "request_id": request_id, "actor": who["identity"], "tool": name, "capability": capability, "version": item["version"], "manifest_digest": item["manifest_digest"], "params_sha256": params_hash})
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=request.timeout_seconds, follow_redirects=False, trust_env=False) as client:
            async with client.stream("POST", target, json=request.params, headers={"X-EVEZ-Request-ID": request_id}) as upstream:
                upstream.raise_for_status()
                raw = bytearray()
                async for chunk in upstream.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise ValueError("Output exceeded configured response limit")
                result = json.loads(bytes(raw))
        errors = list(Draft202012Validator(item["output_schema"]).iter_errors(result))
        if errors:
            raise ValueError("Output schema validation failed")
    except httpx.TimeoutException:
        audit({"event": "tool.invoke.failed", "request_id": request_id, "actor": who["identity"], "tool": name, "reason": "timeout"})
        raise HTTPException(status_code=504, detail={"message": "Tool timeout", "request_id": request_id})
    except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
        audit({"event": "tool.invoke.failed", "request_id": request_id, "actor": who["identity"], "tool": name, "reason": type(exc).__name__})
        raise HTTPException(status_code=502, detail={"message": "Invocation or output validation failed", "request_id": request_id}) from exc
    duration = int((time.monotonic() - started) * 1000)
    result_payload = {"request_id": request_id, "tool": name, "version": item["version"], "duration_ms": duration, "result": result}
    save_result(who["identity"], name, request.idempotency_key, params_hash, result_payload)
    audit({"event": "tool.invoke.succeeded", "request_id": request_id, "actor": who["identity"], "tool": name, "capability": capability, "duration_ms": duration, "result_sha256": digest(result)})
    return result_payload
