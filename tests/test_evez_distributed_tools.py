import json
from pathlib import Path
from fastapi.testclient import TestClient
from distributed_tools import server

ADMIN = {"X-EVEZ-Token": "test-admin", "X-EVEZ-Role": "admin"}
AGENT = {"X-EVEZ-Token": "test-agent", "X-EVEZ-Role": "agent"}
client = TestClient(server.app)

def manifest(endpoint="https://tools.example.org/invoke"):
    return {
        "name": "echo-tool", "version": "1.0.0", "description": "Test tool",
        "service": {"type": "http", "endpoint": endpoint},
        "input_schema": {"type": "object", "required": ["message"], "additionalProperties": False, "properties": {"message": {"type": "string"}}},
        "output_schema": {"type": "object", "required": ["echo"], "properties": {"echo": {"type": "string"}}},
        "capabilities": ["test.echo"], "rate_limit": {"requests_per_minute": 10},
        "auth": {"required": True, "roles": ["agent", "admin"]},
    }

def setup_function():
    server.REGISTRY.clear()
    server.RATE_EVENTS.clear()
    server.ADMIN_TOKEN, server.AGENT_TOKEN, server.READONLY = "test-admin", "test-agent", False
    server.AUDIT_PATH = Path("/tmp/evez-tools-ci-test-audit.jsonl")
    server.AUDIT_PATH.unlink(missing_ok=True)

def test_health_and_auth_required():
    assert client.get("/health").status_code == 200
    assert client.get("/tools").status_code == 401

def test_agent_cannot_register():
    assert client.post("/tools/register", headers=AGENT, json=manifest()).status_code == 403

def test_admin_registers_and_agent_discovers():
    assert client.post("/tools/register", headers=ADMIN, json=manifest()).status_code == 201
    found = client.get("/tools/capabilities/test.echo", headers=AGENT).json()
    assert found["count"] == 1 and found["tools"][0]["name"] == "echo-tool"

def test_local_endpoint_rejected():
    assert client.post("/tools/register", headers=ADMIN, json=manifest("http://127.0.0.1:8080/run")).status_code == 422

def test_readonly_blocks_registration():
    server.READONLY = True
    assert client.post("/tools/register", headers=ADMIN, json=manifest()).status_code == 423

def test_unregister_tombstones_and_audits():
    client.post("/tools/register", headers=ADMIN, json=manifest())
    assert client.delete("/tools/echo-tool", headers=ADMIN).status_code == 200
    assert client.get("/tools", headers=AGENT).json()["count"] == 0
    events = [json.loads(line) for line in server.AUDIT_PATH.read_text().splitlines()]
    assert any(event["event"] == "tool.unregister" for event in events)

def test_bad_invocation_schema_rejected_before_network():
    client.post("/tools/register", headers=ADMIN, json=manifest())
    response = client.post("/tools/echo-tool/invoke", headers=AGENT, json={"params": {"bad": True}})
    assert response.status_code == 422
