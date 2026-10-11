"""EVEZ distributed tool registry reference API.

Read-only by default. Single-process starter; production needs a durable registry,
authenticated peer identity, egress enforcement, and a tamper-evident audit sink.
"""
from __future__ import annotations
import hashlib, hmac, json, os, secrets, time, urllib.parse
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field

READONLY = os.getenv("EVEZ_TOOLS_READONLY", "1").lower() in {"1", "true", "yes", "on"}
ADMIN_TOKEN = os.getenv("EVEZ_ADMIN_TOKEN", "")
AGENT_TOKEN = os.getenv("EVEZ_AGENT_TOKEN", "")
AUDIT_PATH = Path(os.getenv("EVEZ_AUDIT_PATH", "logs/audit.jsonl"))
REGISTRY: dict[str, dict[str, Any]] = {}
RATE_EVENTS: dict[str, deque[float]] = defaultdict(deque)
app = FastAPI(title="EVEZ Distributed Tool Registry", version="1.0.0")

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
    timeout_seconds: int = Field(default=20, ge=1, le=120)

def digest(value: Any) -> str:
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()

def audit(event: dict[str, Any]) -> None:
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), **event}
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as out:
            out.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Audit sink unavailable; request not performed") from exc

def caller(x_evez_token: str | None = Header(default=None),
           x_evez_role: str | None = Header(default=None)) -> dict[str, str]:
    if not x_evez_token or not x_evez_role:
        raise HTTPException(status_code=401, detail="Missing EVEZ credentials")
    if x_evez_role == "admin" and ADMIN_TOKEN and hmac.compare_digest(x_evez_token, ADMIN_TOKEN):
        return {"role": "admin", "identity": "admin-token"}
    if x_evez_role == "agent" and AGENT_TOKEN and hmac.compare_digest(x_evez_token, AGENT_TOKEN):
        return {"role": "agent", "identity": "agent-token"}
    raise HTTPException(status_code=403, detail="Invalid credentials or role")

def admin(who: dict[str, str] = Depends(caller)) -> dict[str, str]:
    if who["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return who

def endpoint_ok(raw: str, kind: str) -> str:
    parsed = urllib.parse.urlsplit(raw)
    allowed = {"http": {"http", "https"}, "grpc": {"grpc", "grpcs"}}[kind]
    if parsed.scheme not in allowed or not parsed.hostname:
        raise HTTPException(status_code=422, detail="Endpoint scheme does not match service type")
    if parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1", "0.0.0.0", "169.254.169.254"}:
        raise HTTPException(status_code=422, detail="Local and link-local endpoints are blocked")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=422, detail="Credentials must not appear in endpoint URLs")
    return raw

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
    return {"status": "healthy", "version": "1.0.0", "readonly": READONLY}

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
    old = REGISTRY.get(manifest.name)
    if old and old["version"] == manifest.version and old["manifest_digest"] != version_digest:
        raise HTTPException(status_code=409, detail="Same name/version cannot change content")
    record = {**payload, "manifest_digest": version_digest, "registered_by": who["identity"]}
    audit({"event": "tool.register", "actor": who["identity"], "tool": manifest.name, "version": manifest.version, "manifest_digest": version_digest})
    REGISTRY[manifest.name] = record
    return {"registered": True, "tool": public(record), "manifest_digest": version_digest}

@app.delete("/tools/{name}")
def unregister(name: str, who: dict[str, str] = Depends(admin)) -> dict[str, Any]:
    if READONLY:
        raise HTTPException(status_code=423, detail="EVEZ_TOOLS_READONLY is enabled")
    item = REGISTRY.get(name)
    if item is None:
        raise HTTPException(status_code=404, detail="Unknown tool")
    audit({"event": "tool.unregister", "actor": who["identity"], "tool": name, "version": item["version"], "manifest_digest": item["manifest_digest"]})
    item["enabled"] = False
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
    throttled(name, item["rate_limit"]["requests_per_minute"])
    target = endpoint_ok(item["service"]["endpoint"], item["service"]["type"])
    if item["service"]["type"] != "http":
        raise HTTPException(status_code=501, detail="gRPC adapter not installed")
    audit({"event": "tool.invoke.started", "request_id": request_id, "actor": who["identity"], "tool": name, "version": item["version"], "manifest_digest": item["manifest_digest"], "params_sha256": digest(request.params)})
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=request.timeout_seconds, follow_redirects=False, trust_env=False) as client:
            response = await client.post(target, json=request.params, headers={"X-EVEZ-Request-ID": request_id})
        response.raise_for_status()
        result = response.json()
        errors = list(Draft202012Validator(item["output_schema"]).iter_errors(result))
        if errors:
            raise ValueError("Output schema validation failed")
    except httpx.TimeoutException as exc:
        audit({"event": "tool.invoke.failed", "request_id": request_id, "actor": who["identity"], "tool": name, "reason": "timeout"})
        raise HTTPException(status_code=504, detail={"message": "Tool timeout", "request_id": request_id}) from exc
    except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
        audit({"event": "tool.invoke.failed", "request_id": request_id, "actor": who["identity"], "tool": name, "reason": type(exc).__name__})
        raise HTTPException(status_code=502, detail={"message": "Invocation or output validation failed", "request_id": request_id}) from exc
    duration = int((time.monotonic() - started) * 1000)
    audit({"event": "tool.invoke.succeeded", "request_id": request_id, "actor": who["identity"], "tool": name, "duration_ms": duration, "result_sha256": digest(result)})
    return {"request_id": request_id, "tool": name, "version": item["version"], "duration_ms": duration, "result": result}
