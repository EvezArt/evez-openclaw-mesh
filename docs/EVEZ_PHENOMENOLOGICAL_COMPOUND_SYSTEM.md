# EVEZ Phenomenological Compound System
Version: 0.1.0 | Status: architecture proposal

## North star

EVEZ is a local-first, evidence-preserving production system in which agents discover authorized services, transform observations into reproducible artifacts, and retain provenance for every derivative. An interpretation is never silently promoted to fact, and a hash is never treated as proof that a claim is true.

The conceptual lineage is Primary Intent Field (PIF) → Harmonic Counterpoint (HCP) → recursive feedback synchronization → geometric/semantic encoding → stabilized artifact → actionable projection → feedback. This is an engineering model until every stage has operational definitions and acceptance tests.

## Product loop

1. Capture files, text, images, audio, video, logs, URLs, sensor readings, tool outputs, and annotations.
2. Fingerprint original bytes; preserve source objects as immutable assets.
3. Describe source, timestamp, operator, authority/consent, capture conditions, media type, and known gaps.
4. Perceive using versioned extractors: OCR, ASR, image regions, scene cuts, audio features, and metadata parsers.
5. Hypothesize: create candidate interpretations linked to supporting and contradicting observations.
6. Compose a directed acyclic graph (DAG) of transformations. Each node records inputs, tool/version, parameters, model/version, policy decision, output digest, timestamps, and status.
7. Validate schema, media integrity, provenance, replayability, cross-view consistency, and required human review.
8. Project outputs: evidence dossiers, contact sheets, transcripts, subtitles, audio renders, 3D proxies, reports, web views, test reports, and deployment bundles.
9. Seal the event in a hash-chained ledger and store the artifact plus manifest.
10. Learn from measured outcomes without modifying prior records.

## Core entities

- Asset: immutable original or derived object, content hash, media type, size, storage URI, retention class.
- Observation: extracted or human-recorded statement tied to assets, method, and confidence.
- Hypothesis: interpretation with explicit support, counterevidence, assumptions, and falsification criteria.
- Transformation: versioned operation with inputs, parameters, tool identity, authorization, outputs, logs, and status.
- Capability: narrowly scoped permission such as media.ocr, audio.transcribe, video.keyframes, evidence.export, or deploy.preview.
- AgentRun: bounded task with objective, budgets, tools, state, retries, and stop conditions.
- ReviewDecision: actor, decision, rationale, scope, timestamp, and artifact IDs.
- LedgerEvent: append-only event committing to its predecessor and canonical payload.

## Asset transmutation model

A transformation is a provenance edge, not an ontological claim. For transformation T with input assets A, parameters P, tool/version V, policy decision D, and outputs O, record T = (A, P, V, D, environment, O, status).

A transformation is reproducible when all inputs can be retrieved, relevant tool/model/runtime versions are pinned, parameters can be replayed, and output digests can be compared under a declared determinism policy. For nondeterministic models, retain the original output and report semantic replay equivalence separately from byte identity.

Use RFC 8785 JSON Canonicalization Scheme (JCS), or another explicitly versioned canonical encoding, before hashing structured manifests. Never hash ambiguous string concatenations. A content digest proves byte identity relative to a digest; it does not independently prove authorship, truth, creation time, or chain of custody.

## Immutable prima materia / digitalus informakea

Operational definition: prima materia is the preserved source object plus its first capture manifest. Derived data may add knowledge but must not mutate the source object. Informakea denotes structured information derived from the source; ideum denotes a hypothesis or conceptual model; provectorvalus denotes a projection into an actionable artifact or external effect.

Invariant: source_asset_id must differ from derived_asset_id, and the derived asset provenance must include the source_asset_id.

The ledger records successful, failed, rejected, superseded, quarantined, and rolled-back transformations. Deletion of sensitive material may be required by policy or law; retain only a permitted tombstone and audit proof, not prohibited content. Immutable means append-only provenance within declared retention and access policies, not a license to retain everything forever.

## Confidence discipline

Keep separate values for extraction_confidence, source_reliability, interpretation_confidence, reproducibility_status, and review_status. Do not collapse them into one opaque score. An edge detector finding a line does not prove a person carved it; a model transcript is not verified speech; a hash is not a truth oracle.

## Plugin and harness portfolio

| Plugin / harness | Input → output | Acceptance test |
|---|---|---|
| evez-ingest | mixed media → immutable asset records | exact digest and source metadata retained |
| evez-provenance | transformation event → verifiable DAG edge | missing input/version fails validation |
| evez-phenomenology | observations and counterevidence → reviewable hypotheses | every hypothesis lists alternatives and falsifiers |
| evez-media-forge | image/audio/video → keyframes, waveform, transcript, contact sheet | files open and manifests link to every input |
| evez-3d-proxy | calibrated views or declared single-view approximation → rotatable model | measured geometry distinguished from inferred surfaces |
| evez-agent-tui | jobs, approvals, logs → terminal dashboard | pause, cancel, inspect, approve, export all work |
| evez-compound-runner | DAG recipe → multiple derived assets | retries are idempotent; partial failures remain visible |
| evez-evidence-export | ledger slice → JSONL/CSV/HTML/ZIP dossier | hashes validate and secrets are redacted |
| evez-policy-gate | identity, capability, context → allow/deny/proposal | unknown identity or capability fails closed |
| evez-replay-lab | event log and pinned artifacts → replay report | divergence is reported, never silently overwritten |

These are proposed modules, not a claim that every plugin already exists. Start with ingest, provenance, compound runner, TUI, and export; add modality plugins behind the same contract.

## Agent TUI

Minimum panes: run queue with state/budget/retries; asset graph with inputs/transforms/outputs and digest status; evidence view with observations, hypotheses, counterevidence, and uncertainty; capability approvals with exact side effects and approver; structured redacted logs correlated by run ID; output gallery with MIME type, digest, open/export actions; and ledger with previous/current hashes and verification result.

Every run has explicit stop conditions: objective met, budget exhausted, policy denied, repeated identical failure, cancellation, or integrity violation. No autonomous loop may continue indefinitely.

## Security and autonomy invariants

- Discovery does not confer invocation permission.
- No ambient shell, Docker socket, Kubernetes admin, or unrestricted network capability.
- Separate read, write, deploy, and credential-management capabilities.
- High-risk actions create a proposal and never self-approve.
- Default local-only and read-only; explicit policy enables a narrower operation.
- Egress allowlists and DNS/IP validation must be enforced at the network boundary, not only in a URL parser.
- Secrets do not belong in manifests, logs, artifacts, or model prompts.
- Output files are atomically written, hashed, and registered only after integrity checks.
- Quarantine untrusted inputs and tool outputs before execution or rendering.
- A kill switch stops new invocations and cancels cancellable jobs.

## Success metrics

Track verified assets per run, provenance completeness, replay success rate, false-positive rate, human correction rate, median time-to-artifact, cost per accepted artifact, policy denials, and unresolved integrity faults. More tokens, tools, agents, or logs are not success by themselves.

## Initial demonstration scenario

Input: a directory containing photos, a short video, notes, and an optional transcript.

Expected results:
1. Source files remain byte-identical and receive SHA-256 digests.
2. Video keyframes, transcript if audio exists, image contact sheet, metadata report, and notes index are separate assets.
3. Each output records input IDs, tool/version, parameters, and digest.
4. The evidence report distinguishes observations from interpretations and marks unknowns.
5. The TUI shows job state and generated assets.
6. A JSONL ledger and portable ZIP dossier verify offline.
7. Replay reports exact or divergent outputs without replacing originals.

The demonstration succeeds only when generated files exist, open correctly, and pass the provenance verifier.
