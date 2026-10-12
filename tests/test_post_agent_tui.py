import base64
import hashlib
import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "post_agent_tui.py"
SPEC = importlib.util.spec_from_file_location("post_agent_tui", MODULE_PATH)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def observation(**overrides):
    item = {
        "id": "obs-1",
        "value": 1.234,
        "unit": "mm",
        "observed_at": "2026-10-12T08:00:00Z",
        "method": "caliper",
        "instrument": "caliper-serial-7",
        "source": "raw/reading-001.txt",
        "raw_value": "1.234 mm",
        "source_content": "1.234 mm",
        "source_sha256": hashlib.sha256(b"1.234 mm").hexdigest(),
        "calibration": "cal-2026-10",
        "uncertainty": "+/- 0.02 mm",
        "replicate_id": "rep-1",
        "operator_or_automation": "test-fixture",
    }
    item.update(overrides)
    return item


class PostAgentAuditTests(unittest.TestCase):
    def test_complete_observation_passes_schema_audit(self):
        result = module.review_observation(observation())
        self.assertEqual(result["state"], "PASS")
        self.assertEqual(result["computed_source_sha256"], hashlib.sha256(b"1.234 mm").hexdigest())

    def test_valid_hash_format_without_raw_source_bytes_does_not_pass(self):
        obs = observation()
        del obs["source_content"]
        result = module.review_observation(obs)
        self.assertEqual(result["state"], "REVIEW_REQUIRED")
        self.assertTrue(any("cannot be independently verified" in issue for issue in result["issues"]))

    def test_mismatched_source_hash_fails(self):
        result = module.review_observation(observation(source_sha256="b" * 64))
        self.assertEqual(result["state"], "FAIL")
        self.assertTrue(any("source_sha256 mismatch" in issue for issue in result["issues"]))

    def test_base64_source_bytes_are_verified(self):
        content = b"instrument=abc\\nreading=1.234 mm\\n"
        obs = observation(
            raw_value="1.234 mm",
            source_content=None,
            source_bytes_base64=base64.b64encode(content).decode("ascii"),
            source_sha256=hashlib.sha256(content).hexdigest(),
        )
        del obs["source_content"]
        self.assertEqual(module.review_observation(obs)["state"], "PASS")

    def test_reported_result_must_link_to_real_observation(self):
        packet = {
            "reported_results": [{"name": "r", "value": 1.234, "unit": "mm", "observation_ids": ["missing"]}],
            "raw_observations": [observation()],
        }
        audit = module.review_packet(packet)
        self.assertEqual(audit["state"], "REVIEW_REQUIRED")
        self.assertTrue(any("references missing observation IDs" in issue for issue in audit["issues"]))

    def test_reported_result_without_link_is_review_required(self):
        packet = {
            "reported_results": [{"name": "r", "value": 1.234, "unit": "mm"}],
            "raw_observations": [observation()],
        }
        audit = module.review_packet(packet)
        self.assertEqual(audit["state"], "REVIEW_REQUIRED")
        self.assertTrue(any("has no linked observation IDs" in issue for issue in audit["issues"]))

    def test_three_decimal_places_without_raw_observation_is_not_pass(self):
        packet = {"reported_results": [{"name": "r", "value": 0.500, "unit": "ratio", "precision": 3}], "raw_observations": []}
        audit = module.review_packet(packet)
        self.assertNotEqual(audit["state"], "PASS")
        self.assertIn("no raw observations", audit["issues"][0])

    def test_missing_calibration_is_review_required(self):
        obs = observation()
        del obs["calibration"]
        self.assertEqual(module.review_observation(obs)["state"], "REVIEW_REQUIRED")

    def test_missing_required_method_fails(self):
        obs = observation()
        del obs["method"]
        self.assertEqual(module.review_observation(obs)["state"], "FAIL")

    def test_bad_source_hash_is_flagged(self):
        result = module.review_observation(observation(source_sha256="not-a-hash"))
        self.assertEqual(result["state"], "FAIL")

    def test_nonfinite_value_fails(self):
        self.assertEqual(module.review_observation(observation(value=float("nan")))["state"], "FAIL")

    def test_duplicate_ids_are_flagged(self):
        packet = {"reported_results": [], "raw_observations": [observation(), observation(source="raw/reading-002.txt")]}
        self.assertIn("duplicate observation IDs", module.review_packet(packet)["issues"][0])

    def test_audit_is_deterministic(self):
        packet = {"packet_id": "p1", "reported_results": [], "raw_observations": [observation()]}
        self.assertEqual(module.review_packet(packet), module.review_packet(packet))

    def test_report_disclaims_truth_claim(self):
        packet = {"reported_results": [{"name": "r", "value": 0.5, "unit": "ratio", "precision": 3}], "raw_observations": []}
        rendered = module.render(packet, module.review_packet(packet))
        self.assertIn("display precision, not measurement validity", rendered)
        self.assertIn("NO RAW OBSERVATIONS PROVIDED", rendered)

    def test_render_shows_bounded_raw_source_preview(self):
        packet = {
            "reported_results": [{"name": "reading", "value": 1.234, "unit": "mm", "observation_ids": ["obs-1"]}],
            "raw_observations": [observation()],
        }
        rendered = module.render(packet, module.review_packet(packet))
        self.assertIn("source_content_utf8_preview", rendered)
        self.assertIn("1.234 mm", rendered)


if __name__ == "__main__":
    unittest.main()
