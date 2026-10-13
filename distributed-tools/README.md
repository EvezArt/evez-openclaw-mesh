# EVEZ Distributed Tools v1

A safety-first reference architecture for treating tools as discoverable services across the EVEZ mesh.

## Contract
Each tool has a stable name and semantic version, service transport/endpoint, strict input and output JSON Schemas, capabilities, rate limit, and allowed roles. Discovery must never be treated as authorization. Invocation must authenticate the caller, authorize the requested capability, validate input, enforce limits and timeouts, validate output, and write a redacted audit record with request ID, manifest digest, and result digest.

Conceptual API: `GET /tools`, `GET /tools/{name}`, `GET /tools/{name}/health`, `GET /tools/capabilities/{capability}`, `POST /tools/register`, `POST /tools/{name}/invoke`, and `DELETE /tools/{name}`. Writes and unregister operations require an administrator identity; unregistration should tombstone/disable rather than erase audit history.

## Hermes/OpenClaw integration
Hermes is already a governed adaptive runtime with explicit capability gates, proposals, approval, an append-only event spine, and rollback. EVEZ tool invocation must preserve those controls. Do not grant tools arbitrary shell, unrestricted filesystem, Docker socket, Kubernetes, or network access by default. High-risk capabilities such as deployment and permission changes require a proposal and explicit approval.

## Deployment requirements
This directory currently defines the implementation contract, not an installed production service. Before production, require authenticated peer identity or mTLS, least-privilege capability grants, schema validation, endpoint/egress allowlists, DNS-rebinding/SSRF defenses, bounded concurrency/payloads/timeouts, a kill switch, durable shared registry storage, and tamper-evident audit storage. Never place tokens in manifests, logs, or source control. Keep global read-only mode on until policy and access controls have been validated.

## Local execution
The standalone reference implementation and test suite are provided in the separate `evez-tools-source.zip` artifact. It is intentionally not wired into this repository's live gateway because the deployed Hermes/OpenClaw endpoints and native adapter contracts have not been verified in this GitHub inspection.