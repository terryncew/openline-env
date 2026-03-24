"""
tests/test_openline_env.py
--------------------------
Full test coverage for openline-env.

Run: python -m unittest discover -s tests
Or:  pytest tests/ -v  (if pytest is available)
"""

import json
import sys
import os
import tempfile
import unittest
from unittest.mock import patch


class TestFingerprint(unittest.TestCase):

    def test_collect_returns_fingerprint(self):
        from openline_env.fingerprint import collect
        fp = collect()
        self.assertEqual(fp.python_version, sys.version)
        self.assertTrue(fp.fingerprint_hash)
        self.assertEqual(len(fp.fingerprint_hash), 64)

    def test_fingerprint_hash_is_deterministic(self):
        from openline_env.fingerprint import collect
        fp1 = collect()
        fp2 = collect()
        self.assertEqual(fp1.fingerprint_hash, fp2.fingerprint_hash)

    def _base_fp_kwargs(self, litellm_version):
        return dict(
            python_version="3.11.0",
            platform_summary="Linux",
            os_release="5.15",
            critical_packages={"litellm": litellm_version},
            lockfile_hash=None,
            lockfile_source=None,
            container_hint=None,
        )

    def test_fingerprint_hash_changes_with_package_change(self):
        from openline_env.fingerprint import EnvFingerprint
        fp1 = EnvFingerprint(**self._base_fp_kwargs("1.82.6"))
        fp2 = EnvFingerprint(**self._base_fp_kwargs("1.82.8"))
        self.assertNotEqual(fp1.fingerprint_hash, fp2.fingerprint_hash)

    def test_fingerprint_hash_changes_with_python_version(self):
        from openline_env.fingerprint import EnvFingerprint
        base = dict(
            platform_summary="Linux", os_release="5.15",
            critical_packages={"openai": "1.0.0"},
            lockfile_hash=None, lockfile_source=None, container_hint=None,
        )
        fp1 = EnvFingerprint(python_version="3.11.0", **base)
        fp2 = EnvFingerprint(python_version="3.12.0", **base)
        self.assertNotEqual(fp1.fingerprint_hash, fp2.fingerprint_hash)

    def test_lockfile_hash_set_when_file_provided(self):
        from openline_env.fingerprint import collect
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("litellm==1.82.6\nopenai==1.0.0\n")
            path = f.name
        try:
            fp = collect(lockfile_path=path)
            self.assertIsNotNone(fp.lockfile_hash)
            self.assertEqual(fp.lockfile_source, path)
        finally:
            os.unlink(path)

    def test_lockfile_hash_changes_with_content(self):
        from openline_env.fingerprint import _hash_lockfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("litellm==1.82.6\n")
            p1 = f.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("litellm==1.82.8\n")
            p2 = f.name
        try:
            self.assertNotEqual(_hash_lockfile(p1), _hash_lockfile(p2))
        finally:
            os.unlink(p1)
            os.unlink(p2)

    def test_lockfile_hash_none_for_missing_file(self):
        from openline_env.fingerprint import _hash_lockfile
        self.assertIsNone(_hash_lockfile("/no/such/path/requirements.txt"))

    def test_to_dict_contains_required_fields(self):
        from openline_env.fingerprint import collect
        d = collect().to_dict()
        for key in [
            "python_version", "platform_summary", "os_release",
            "critical_packages", "lockfile_hash", "lockfile_source",
            "container_hint", "fingerprint_hash",
        ]:
            self.assertIn(key, d)

    def test_summary_string_format(self):
        from openline_env.fingerprint import collect
        s = collect().summary()
        self.assertIn("py=", s)
        self.assertIn("fp=", s)

    def test_extra_packages_included(self):
        from openline_env.fingerprint import collect
        fp = collect(extra_packages=["setuptools"])
        self.assertIn("setuptools", fp.critical_packages)

    def test_missing_packages_excluded(self):
        from openline_env.fingerprint import collect
        fp = collect(extra_packages=["not-a-real-package-xyzabc"])
        self.assertNotIn("not-a-real-package-xyzabc", fp.critical_packages)

    def test_container_hint_from_env_var(self):
        from openline_env.fingerprint import _container_digest
        with patch.dict(os.environ, {"DOCKER_IMAGE_DIGEST": "sha256:abc123"}):
            self.assertEqual(_container_digest(), "sha256:abc123")


class TestDenylist(unittest.TestCase):

    def test_known_bad_litellm_1_82_7(self):
        from openline_env.denylist import check
        hits = check({"litellm": "1.82.7"})
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].package, "litellm")
        self.assertEqual(hits[0].severity, "critical")

    def test_known_bad_litellm_1_82_8(self):
        from openline_env.denylist import check
        self.assertEqual(len(check({"litellm": "1.82.8"})), 1)

    def test_clean_litellm_version_not_flagged(self):
        from openline_env.denylist import check
        self.assertEqual(len(check({"litellm": "1.82.6"})), 0)

    def test_is_clean_true(self):
        from openline_env.denylist import is_clean
        self.assertTrue(is_clean({"openai": "1.0.0"}))

    def test_is_clean_false_on_bad_version(self):
        from openline_env.denylist import is_clean
        self.assertFalse(is_clean({"litellm": "1.82.8"}))

    def test_is_clean_empty_packages(self):
        from openline_env.denylist import is_clean
        self.assertTrue(is_clean({}))

    def test_hit_str_format(self):
        from openline_env.denylist import check
        hit = check({"litellm": "1.82.7"})[0]
        self.assertIn("litellm", str(hit))
        self.assertIn("CRITICAL", str(hit))

    def test_multiple_packages_one_bad(self):
        from openline_env.denylist import check
        hits = check({"openai": "1.0.0", "litellm": "1.82.8", "anthropic": "0.20.0"})
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].package, "litellm")

    def test_unknown_package_not_flagged(self):
        from openline_env.denylist import check
        self.assertEqual(len(check({"some-unknown-pkg": "9.9.9"})), 0)

    def test_hit_has_safedep_source(self):
        from openline_env.denylist import check
        hits = check({"litellm": "1.82.7"})
        self.assertIsNotNone(hits[0].source)
        self.assertIn("safedep", hits[0].source.lower())


class TestReceipt(unittest.TestCase):

    def _fp(self, litellm_version="1.82.6"):
        from openline_env.fingerprint import EnvFingerprint
        return EnvFingerprint(
            python_version="3.11.0", platform_summary="Linux", os_release="5.15",
            critical_packages={"litellm": litellm_version},
            lockfile_hash=None, lockfile_source=None, container_hint=None,
        )

    def test_build_returns_valid_structure(self):
        from openline_env.receipt import build
        r = build(payload={"claim": "test", "result": "ok"})
        self.assertEqual(r["schema"], "openline.science.v1")
        for key in ("receipt_hash", "env", "payload", "timestamp_utc"):
            self.assertIn(key, r)

    def test_receipt_hash_is_64_char_hex(self):
        from openline_env.receipt import build
        h = build(payload={"x": 1})["receipt_hash"]
        self.assertEqual(len(h), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_same_payload_same_env_same_hash(self):
        from openline_env.receipt import build
        fp = self._fp()
        r1 = build(payload={"result": "pass"}, fp=fp)
        r2 = build(payload={"result": "pass"}, fp=fp)
        self.assertEqual(r1["receipt_hash"], r2["receipt_hash"])

    def test_same_payload_different_deps_different_hash(self):
        """Core guarantee: same output, different deps → different receipt."""
        from openline_env.receipt import build
        r1 = build(payload={"result": "pass"}, fp=self._fp("1.82.6"))
        r2 = build(payload={"result": "pass"}, fp=self._fp("1.82.8"))
        self.assertNotEqual(r1["receipt_hash"], r2["receipt_hash"])

    def test_denylist_hit_reflected_in_receipt(self):
        from openline_env.receipt import build
        r = build(payload={"result": "pass"}, fp=self._fp("1.82.8"))
        self.assertFalse(r["env"]["env_clean"])
        self.assertEqual(len(r["env"]["denylist_hits"]), 1)
        self.assertEqual(r["env"]["denylist_hits"][0]["package"], "litellm")

    def test_clean_env_flag(self):
        from openline_env.receipt import build
        r = build(payload={"result": "pass"}, fp=self._fp("1.82.6"))
        self.assertTrue(r["env"]["env_clean"])
        self.assertEqual(r["env"]["denylist_hits"], [])

    def test_strict_mode_raises_on_bad_package(self):
        from openline_env.receipt import build
        with self.assertRaises(RuntimeError) as ctx:
            build(payload={"result": "pass"}, fp=self._fp("1.82.7"), strict=True)
        self.assertIn("known-bad", str(ctx.exception))

    def test_strict_mode_passes_clean_env(self):
        from openline_env.receipt import build
        r = build(payload={"result": "pass"}, fp=self._fp("1.82.6"), strict=True)
        self.assertTrue(r["env"]["env_clean"])

    def test_receipt_json_serializable(self):
        from openline_env.receipt import build
        r = build(payload={"x": 1})
        self.assertGreater(len(json.dumps(r)), 0)

    def test_env_block_has_fingerprint_fields(self):
        from openline_env.receipt import build
        fp_block = build(payload={"x": 1})["env"]["fingerprint"]
        for key in ("python_version", "fingerprint_hash", "critical_packages"):
            self.assertIn(key, fp_block)


class TestVerify(unittest.TestCase):

    def _fp(self, v):
        from openline_env.fingerprint import EnvFingerprint
        return EnvFingerprint(
            python_version="3.11.0", platform_summary="Linux", os_release="5.15",
            critical_packages={"litellm": v},
            lockfile_hash=None, lockfile_source=None, container_hint=None,
        )

    def test_identical_receipts_match(self):
        from openline_env.receipt import build, verify
        fp = self._fp("1.82.6")
        diff = verify(
            build(payload={"r": "pass"}, fp=fp),
            build(payload={"r": "pass"}, fp=fp),
        )
        self.assertTrue(diff["hashes_match"])
        self.assertFalse(diff["env_diverged"])

    def test_env_divergence_detected(self):
        from openline_env.receipt import build, verify
        diff = verify(
            build(payload={"r": "pass"}, fp=self._fp("1.82.6")),
            build(payload={"r": "pass"}, fp=self._fp("1.82.8")),
        )
        self.assertTrue(diff["env_diverged"])
        self.assertFalse(diff["hashes_match"])
        self.assertTrue(diff["payload_hashes_match"])

    def test_payload_divergence_detected(self):
        from openline_env.receipt import build, verify
        fp = self._fp("1.82.6")
        diff = verify(
            build(payload={"r": "pass"}, fp=fp),
            build(payload={"r": "fail"}, fp=fp),
        )
        self.assertTrue(diff["payload_diverged"])
        self.assertFalse(diff["env_diverged"])

    def test_denylist_hits_surfaced_in_verify(self):
        from openline_env.receipt import build, verify
        diff = verify(
            build(payload={"x": 1}, fp=self._fp("1.82.6")),
            build(payload={"x": 1}, fp=self._fp("1.82.8")),
        )
        self.assertEqual(diff["denylist_hits_a"], [])
        self.assertEqual(len(diff["denylist_hits_b"]), 1)

    def test_hashes_included_in_diff(self):
        from openline_env.receipt import build, verify
        fp = self._fp("1.82.6")
        r = build(payload={"x": 1}, fp=fp)
        diff = verify(r, r)
        self.assertEqual(diff["receipt_hash_a"], diff["receipt_hash_b"])
        self.assertEqual(diff["fingerprint_hash_a"], diff["fingerprint_hash_b"])


class TestIntegration(unittest.TestCase):

    def test_full_flow_build_and_verify(self):
        from openline_env import build, verify, collect
        fp = collect()
        r = build(payload={"agent_id": "test", "output": "42"}, fp=fp)
        self.assertEqual(r["schema"], "openline.science.v1")
        self.assertEqual(r["env"]["fingerprint"]["fingerprint_hash"], fp.fingerprint_hash)
        self.assertEqual(len(r["receipt_hash"]), 64)
        diff = verify(r, r)
        self.assertTrue(diff["hashes_match"])

    def test_discriminating_guarantee(self):
        """
        Same agent output + different dependency state = different receipt hash.
        This is the spec's core test.
        """
        from openline_env.fingerprint import EnvFingerprint
        from openline_env.receipt import build

        payload = {"output": "the same result"}
        base = dict(
            python_version="3.11.0", platform_summary="Linux", os_release="5.15",
            lockfile_hash=None, lockfile_source=None, container_hint=None,
        )
        fp_clean = EnvFingerprint(critical_packages={"litellm": "1.82.6", "openai": "1.0.0"}, **base)
        fp_bad   = EnvFingerprint(critical_packages={"litellm": "1.82.8", "openai": "1.0.0"}, **base)

        r1 = build(payload=payload, fp=fp_clean)
        r2 = build(payload=payload, fp=fp_bad)

        self.assertNotEqual(r1["receipt_hash"], r2["receipt_hash"])
        self.assertTrue(r1["env"]["env_clean"])
        self.assertFalse(r2["env"]["env_clean"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
