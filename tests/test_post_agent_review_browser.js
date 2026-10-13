"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const { TextEncoder, TextDecoder } = require("node:util");

const html = fs.readFileSync(path.join(__dirname, "..", "tools", "post-agent-review.html"), "utf8");
const match = html.match(/<script>\s*([\s\S]*?)\s*<\/script>/);
assert.ok(match, "reviewer must contain an inline script");
const script = match[1];
new vm.Script(script, { filename: "post-agent-review.html" });

function makeHarness() {
  const elements = new Map();
  function element(id) {
    if (elements.has(id)) return elements.get(id);
    const listeners = new Map();
    const classes = new Set();
    const el = {
      id, value: "", textContent: "", innerHTML: "", files: [],
      listeners,
      classList: {
        add(name) { classes.add(name); },
        remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); },
      },
      addEventListener(event, callback) {
        if (!listeners.has(event)) listeners.set(event, []);
        listeners.get(event).push(callback);
      },
      async dispatch(event, payload = {}) {
        for (const callback of listeners.get(event) || []) await callback({ target: el, ...payload });
      },
      click() { return this.dispatch("click"); },
    };
    elements.set(id, el);
    return el;
  }
  const document = {
    getElementById: element,
    createElement(tag) { return { tagName: tag, href: "", download: "", click() {}, style: {} }; },
  };
  const sandbox = {
    document, crypto: webcrypto, TextEncoder, TextDecoder,
    atob: globalThis.atob.bind(globalThis), btoa: globalThis.btoa.bind(globalThis),
    navigator: { clipboard: { async writeText() {} } },
    Blob, URL, setTimeout, Uint8Array,
  };
  vm.runInNewContext(script, sandbox, { timeout: 1000, filename: "post-agent-review.html" });
  return { element, elements };
}
const hex = bytes => Buffer.from(bytes).toString("hex");
async function sha256(bytes) {
  const digest = await webcrypto.subtle.digest("SHA-256", bytes);
  return hex(new Uint8Array(digest));
}
async function validObservation(overrides = {}) {
  const source = "sensor=caliper-7;reading=1.234 mm";
  return {
    id: "obs-1", value: 1.234, unit: "mm",
    observed_at: "2026-10-12T08:00:00Z", method: "caliper",
    instrument: "caliper-7", source: "fixture.txt", raw_value: "1.234 mm",
    source_content: source, source_sha256: await sha256(new TextEncoder().encode(source)),
    calibration: "cal-2026-10", uncertainty: "+/- 0.02 mm",
    replicate_id: "rep-1", operator_or_automation: "test",
    ...overrides,
  };
}
async function runReview(packet) {
  const h = makeHarness();
  h.element("packet").value = JSON.stringify(packet);
  await h.element("review").click();
  return h;
}
const linkedResult = (observationIds = ["obs-1"]) =>
  ({ name: "reading", value: 1.234, unit: "mm", observation_ids: observationIds });

test("missing observations never pass on reported precision alone", async () => {
  const h = makeHarness();
  await h.element("demo").click();
  await h.element("review").click();
  assert.match(h.element("status").innerHTML, /REVIEW_REQUIRED/);
  assert.match(h.element("flags").innerHTML, /no raw observations/i);
});

test("valid UTF-8 source bytes and linked result pass schema-level checks", async () => {
  const obs = await validObservation();
  const h = await runReview({ packet_id: "valid", reported_results: [linkedResult()], raw_observations: [obs] });
  assert.match(h.element("status").innerHTML, /SCHEMA CHECK PASSED/);
  assert.match(h.element("observations").innerHTML, /class="badge PASS"/);
  assert.match(h.element("observations").innerHTML, new RegExp(obs.source_sha256));
});

test("declared digest mismatch fails", async () => {
  const obs = await validObservation({ source_sha256: "b".repeat(64) });
  const h = await runReview({ reported_results: [linkedResult()], raw_observations: [obs] });
  assert.match(h.element("status").innerHTML, /FAIL/);
  assert.match(h.element("flags").innerHTML, /Source hash mismatch/);
});

test("canonical base64 verifies exact non-UTF-8 source bytes", async () => {
  const bytes = Uint8Array.from([0, 255, 65, 10]);
  const raw = Buffer.from(bytes).toString("base64");
  const obs = await validObservation();
  delete obs.source_content;
  obs.source_bytes_base64 = raw;
  obs.source_sha256 = await sha256(bytes);
  const h = await runReview({ reported_results: [linkedResult()], raw_observations: [obs] });
  assert.match(h.element("status").innerHTML, /SCHEMA CHECK PASSED/);
  assert.match(h.element("observations").innerHTML, /binary data: 4 bytes/);
});

test("malformed base64 fails rather than silently hashing another representation", async () => {
  const obs = await validObservation();
  delete obs.source_content;
  obs.source_bytes_base64 = "!!!!";
  const h = await runReview({ reported_results: [linkedResult()], raw_observations: [obs] });
  assert.match(h.element("status").innerHTML, /FAIL/);
  assert.match(h.element("flags").innerHTML, /canonical base64|invalid source bytes/i);
});

test("source preview is bounded and truncation is visible", async () => {
  const source = "X".repeat(5000);
  const obs = await validObservation({
    source_content: source,
    source_sha256: await sha256(new TextEncoder().encode(source)),
  });
  const h = await runReview({ reported_results: [linkedResult()], raw_observations: [obs] });
  const rendered = h.element("observations").innerHTML;
  assert.match(rendered, /preview truncated/);
  assert.ok(rendered.length < 6000, "rendered preview must not contain the full source");
});

test("oversized pasted packet is rejected before JSON parsing", async () => {
  const h = makeHarness();
  h.element("packet").value = " ".repeat(5 * 1024 * 1024 + 1);
  await h.element("review").click();
  assert.match(h.element("error").textContent, /exceeds 5 MiB/);
  assert.equal(h.element("results").classList.contains("hidden"), true);
});

test("dangling result links and duplicate observation IDs are flagged", async () => {
  const first = await validObservation();
  const second = await validObservation({ source: "other.txt" });
  const h = await runReview({
    reported_results: [linkedResult(["missing-id"])],
    raw_observations: [first, second],
  });
  assert.match(h.element("status").innerHTML, /REVIEW_REQUIRED/);
  assert.match(h.element("flags").innerHTML, /Duplicate observation IDs/);
  assert.match(h.element("flags").innerHTML, /references missing observation IDs/);
});

test("attacker-controlled packet and result names are escaped", async () => {
  const h = await runReview({
    packet_id: '<img src=x onerror="alert(1)">',
    reported_results: [{ name: "<script>alert(1)</script>", value: 1, unit: "x", observation_ids: [] }],
    raw_observations: [],
  });
  assert.match(h.element("status").innerHTML, /&lt;img/);
  assert.doesNotMatch(h.element("status").innerHTML, /<img src=x/);
  assert.match(h.element("reported").innerHTML, /&lt;script&gt;/);
  assert.doesNotMatch(h.element("reported").innerHTML, /<script>alert/);
});

test("oversized source payload is rejected", async () => {
  const source = "A".repeat(2 * 1024 * 1024 + 1);
  const obs = await validObservation({ source_content: source, source_sha256: "a".repeat(64) });
  const h = await runReview({ reported_results: [linkedResult()], raw_observations: [obs] });
  assert.match(h.element("status").innerHTML, /FAIL/);
  assert.match(h.element("flags").innerHTML, /source payload exceeds 2 MiB/);
});

test("review script syntax is valid", () => {
  assert.ok(script.length > 1000);
  new vm.Script(script, { filename: "post-agent-review.html" });
});
