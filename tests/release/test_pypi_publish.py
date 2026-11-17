"""Offline PyPI job gates and data-only preflight checks; never invoke a publisher."""

import ast
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml
from release_fixture import NAMES, make_release, write_manifest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = yaml.load((ROOT / ".github/workflows/release.yml").read_text(), Loader=yaml.BaseLoader)
JOB = WORKFLOW["jobs"]["pypi"]


def context():
    return {
        "github": {
            "event_name": "push",
            "repository": "Defense-Exploration-Holdings/octetrail",
            "event": {
                "repository": {"id": 1457516742, "private": False, "default_branch": "main"},
                "created": True,
                "deleted": False,
                "forced": False,
            },
            "ref_type": "tag",
            "ref_protected": True,
            "run_attempt": "1",
        },
        "needs": {
            "build": {"result": "success", "outputs": {"publish": "true", "artifact-id": "77"}}
        },
        "vars": {"PYPI_PUBLISHING_ENABLED": "true", "WHEEL_RELEASES_ENABLED": "true"},
    }


def number(value):
    if value is None or value == "":
        return 0
    if type(value) in (bool, int, float):
        return int(value) if type(value) is bool else value
    try:
        result = json.loads(value)
        return result if type(result) in (int, float) else math.nan
    except (ValueError, TypeError):
        return math.nan


def job_guard(expression, data):
    """Only this workflow's conjunctions, equality and inequality, using documented rules.

    Missing properties are empty strings, string comparison ignores case, and
    differently typed equality operands are coerced to numbers. Not a general
    Actions interpreter; actionlint checks the workflow's syntax separately.
    """
    results = []
    for term in expression.split("&&"):
        match = re.fullmatch(r"\s*([A-Za-z0-9_.-]+)\s+(==|!=)\s+(.+?)\s*", term)
        if not match:
            raise ValueError("unsupported test expression")
        field, operator, literal = match.groups()
        value = data
        for name in field.split("."):
            value = value.get(name, "") if isinstance(value, dict) else ""
        expected = {"true": True, "false": False}.get(literal)
        if expected is None:
            expected = ast.literal_eval(literal)
        if isinstance(value, str) and isinstance(expected, str):
            equal = value.lower() == expected.lower()
        elif type(value) is type(expected):
            equal = value == expected
        else:
            equal = number(value) == number(expected)
        results.append(equal if operator == "==" else not equal)
    return all(results)


def inline(step):
    return step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]


class PypiGateTests(unittest.TestCase):
    def test_opt_in_is_independent_and_missing_or_false_is_off(self):
        data = context()
        self.assertTrue(job_guard(JOB["if"], data))
        for value in ("", "false", "0", "yes"):
            data["vars"]["PYPI_PUBLISHING_ENABLED"] = value
            self.assertFalse(job_guard(JOB["if"], data))
            self.assertTrue(job_guard(WORKFLOW["jobs"]["release"]["if"], data))
        del data["vars"]["PYPI_PUBLISHING_ENABLED"]
        self.assertFalse(job_guard(JOB["if"], data))
        data = context()
        data["vars"] = {"PYPI_PUBLISHING_ENABLED": "true"}
        self.assertTrue(job_guard(JOB["if"], data))
        self.assertFalse(job_guard(WORKFLOW["jobs"]["release"]["if"], data))

    def test_github_string_case_and_numeric_context_semantics(self):
        data = context()
        data["vars"]["PYPI_PUBLISHING_ENABLED"] = "TRUE"
        self.assertTrue(job_guard(JOB["if"], data))
        data["github"]["run_attempt"] = 1
        self.assertTrue(job_guard(JOB["if"], data))
        data["github"]["run_attempt"] = "2"
        self.assertFalse(job_guard(JOB["if"], data))

    def test_pr_manual_branch_other_repo_and_unprotected_cannot_publish(self):
        for field, value in (
            ("event_name", "pull_request"),
            ("event_name", "workflow_dispatch"),
            ("repository", "example/octetrail"),
            ("ref_type", "branch"),
            ("ref_protected", False),
        ):
            data = context()
            data["github"][field] = value
            with self.subTest(field=field, value=value):
                self.assertFalse(job_guard(JOB["if"], data))
        for field, value in (("private", True), ("id", 1), ("default_branch", "other")):
            data = context()
            data["github"]["event"]["repository"][field] = value
            self.assertFalse(job_guard(JOB["if"], data))

    def test_only_validated_successful_initial_push_and_artifact_are_eligible(self):
        for field, value in (("created", False), ("deleted", True), ("forced", True)):
            data = context()
            data["github"]["event"][field] = value
            self.assertFalse(job_guard(JOB["if"], data))
        for status in ("failure", "cancelled", "skipped", ""):
            data = context()
            data["needs"]["build"]["result"] = status
            self.assertFalse(job_guard(JOB["if"], data))
        for outputs in ({}, {"publish": "false", "artifact-id": "77"}, {"publish": "true"}):
            data = context()
            data["needs"]["build"]["outputs"] = outputs
            self.assertFalse(job_guard(JOB["if"], data))

    def test_permissions_environment_same_run_and_pinned_publisher(self):
        self.assertEqual(WORKFLOW["permissions"], {"contents": "read"})
        self.assertEqual(JOB["permissions"], {"id-token": "write"})
        self.assertEqual(JOB["environment"]["name"], "pypi")
        self.assertEqual(JOB["needs"], "build")
        self.assertEqual(
            [name for name, job in WORKFLOW["jobs"].items() if "id-token" in job["permissions"]],
            ["pypi"],
        )
        self.assertEqual(WORKFLOW["jobs"]["release"]["permissions"], {"contents": "write"})
        self.assertEqual(
            JOB["steps"][1]["with"],
            {
                "artifact-ids": "${{ needs.build.outputs.artifact-id }}",
                "path": "release",
            },
        )
        self.assertEqual(
            JOB["steps"][3]["uses"],
            "pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086",
        )
        self.assertEqual(
            JOB["steps"][3]["with"],
            {
                "packages-dir": "release/dist/",
                "skip-existing": "false",
                "verify-metadata": "true",
                "attestations": "true",
                "verbose": "false",
            },
        )
        for step in JOB["steps"]:
            self.assertNotIn("continue-on-error", step)
            self.assertNotIn("if", step)
            self.assertNotIn("secrets", str(step))
            self.assertNotIn("checkout", step.get("uses", ""))
            self.assertNotIn("tools/", step.get("run", ""))
            self.assertNotIn("pip install", step.get("run", ""))
            self.assertFalse(
                any(key in step.get("env", {}) for key in ("GH_TOKEN", "PYPI_API_TOKEN"))
            )


class PypiPreflightTests(unittest.TestCase):
    def model(
        self,
        *,
        changes=None,
        missing=None,
        extra=False,
        changed=False,
        symlink=False,
        missing_dist=False,
        relisted=False,
        optimized=False,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest = make_release(root)
            dist = root / "release/dist"
            # Synthetic process values only. Do not inherit deployment settings or credentials.
            env = {
                "PATH": os.defpath,
                "VERSION": "0.1.0",
                "RELEASE_TAG": "v0.1.0",
                "ARTIFACT_ID": "77",
                "MANIFEST_SHA256": digest,
            }
            env.update(changes or {})
            if missing:
                (dist / NAMES[missing]).unlink()
            if extra:
                (dist / "ordinary.tar.gz").write_bytes(b"unexpected extra fixture")
            if changed:
                (dist / NAMES[0]).write_bytes(b"different benign fixture")
            if relisted:
                (dist / NAMES[0]).unlink()
                env["MANIFEST_SHA256"] = write_manifest(root)
            if symlink:
                path = dist / NAMES[0]
                original = root / "ordinary.bin"
                path.rename(original)
                path.symlink_to(original)
            if missing_dist:
                for path in dist.iterdir():
                    path.unlink()
                dist.rmdir()
            command = [sys.executable, "-B", "-I", *(["-O"] if optimized else []), "-c"]
            results = []
            # Execute only the two stdlib preflight snippets, never Actions or PyPI code.
            for index in (0, 2):
                result = subprocess.run(
                    command + [inline(JOB["steps"][index])],
                    cwd=root,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                results.append(result)
                if result.returncode:
                    break
            return results

    def test_valid_release_passes_both_preflight_steps(self):
        for optimized in (False, True):
            results = self.model(optimized=optimized)
            self.assertEqual(len(results), 2)
            self.assertTrue(all(r.returncode == 0 for r in results))

    def test_wrong_missing_versions_tags_ids_and_digests_fail_before_download(self):
        for changes in (
            {"VERSION": ""},
            {"VERSION": "0.1.0a1"},
            {"RELEASE_TAG": "v0.2.0"},
            {"ARTIFACT_ID": ""},
            {"ARTIFACT_ID": "0"},
            {"ARTIFACT_ID": "different"},
            {"MANIFEST_SHA256": ""},
            {"MANIFEST_SHA256": "short"},
        ):
            results = self.model(changes=changes, optimized=True)
            self.assertEqual(len(results), 1)
            self.assertNotEqual(results[0].returncode, 0)

    def test_missing_extra_changed_and_nonregular_artifacts_fail_before_publisher(self):
        for case in (
            {"missing": 1},
            {"relisted": True},
            {"extra": True},
            {"changes": {"MANIFEST_SHA256": "0" * 64}},
            {"changed": True},
            {"symlink": True},
            {"missing_dist": True},
        ):
            with self.subTest(case=case):
                results = self.model(**case, optimized=True)
                self.assertEqual(len(results), 2)
                self.assertEqual(results[0].returncode, 0)
                self.assertNotEqual(results[1].returncode, 0)


if __name__ == "__main__":
    unittest.main()
