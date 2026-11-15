"""Offline checks for release eligibility, artifacts and workflow isolation."""

import ast
import base64
import copy
import csv
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_ci", ROOT / "tools/release_ci.py")
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)
CHECK_SPEC = importlib.util.spec_from_file_location("check_wheel", ROOT / "tools/check_wheel.py")
C = importlib.util.module_from_spec(CHECK_SPEC)
CHECK_SPEC.loader.exec_module(C)


def environment():
    return {
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": R.CANONICAL,
        "GITHUB_REF_TYPE": "tag",
        "RELEASE_REF_PROTECTED": "true",
        "GITHUB_REF": "refs/tags/v0.1.0",
        "GITHUB_RUN_ATTEMPT": "1",
    }


def event():
    return {
        "repository": {
            "full_name": R.CANONICAL,
            "id": R.REPOSITORY_ID,
            "private": False,
            "default_branch": "main",
        },
        "created": True,
        "deleted": False,
        "forced": False,
        "ref": "refs/tags/v0.1.0",
    }


def evaluate_guard(expression, context):
    """Evaluate the workflow's restricted conjunction of exact comparisons."""
    results = []
    for term in expression.split("&&"):
        field, literal = term.strip().split(" == ")
        value = context
        for name in field.split("."):
            value = value[name]
        expected = {"true": True, "false": False}.get(literal)
        if expected is None:
            expected = ast.literal_eval(literal)
        results.append(type(value) is type(expected) and value == expected)
    return all(results)


class GateTests(unittest.TestCase):
    def test_only_matching_protected_public_tag_is_candidate(self):
        self.assertTrue(R.publication_candidate(environment(), event(), "0.1.0"))

    def test_other_event_repo_visibility_ref_and_attempt_cannot_publish(self):
        changes = {
            "GITHUB_EVENT_NAME": ("pull_request", "workflow_dispatch", "workflow_call"),
            "GITHUB_REPOSITORY": ("example/octetrail", "example/private-project", ""),
            "GITHUB_REF_TYPE": ("branch", ""),
            "RELEASE_REF_PROTECTED": ("false", "", "True"),
            "GITHUB_REF": ("refs/heads/main", "refs/tags/v0.1.1", "refs/tags/0.1.0"),
            "GITHUB_RUN_ATTEMPT": ("2", ""),
        }
        for key, values in changes.items():
            for value in values:
                env = {**environment(), key: value}
                with self.subTest(key=key, value=value):
                    self.assertFalse(R.publication_candidate(env, event(), "0.1.0"))

    def test_event_payload_must_match_canonical_repository_and_initial_push(self):
        for key, value in (
            ("private", True),
            ("private", None),
            ("id", 1),
            ("full_name", "example/octetrail"),
            ("default_branch", "other"),
        ):
            data = event()
            data["repository"][key] = value
            self.assertFalse(R.publication_candidate(environment(), data, "0.1.0"))
        for key, value in (
            ("created", False),
            ("deleted", True),
            ("forced", True),
            ("ref", "refs/heads/main"),
        ):
            data = {**event(), key: value}
            self.assertFalse(R.publication_candidate(environment(), data, "0.1.0"))
        self.assertFalse(R.publication_candidate(environment(), {}, "0.1.0"))

    def test_project_and_both_cargo_versions_must_match(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bindings/python").mkdir(parents=True)
            (root / "python/octetrail").mkdir(parents=True)
            (root / "python/octetrail/__init__.py").write_text('__version__="0.1.0"\n')
            (root / "pyproject.toml").write_text('[project]\nname="octetrail"\nversion="0.1.0"\n')
            for name in ("Cargo.toml", "bindings/python/Cargo.toml"):
                (root / name).write_text('[package]\nversion="0.1.0"\n')
            self.assertEqual(R.source_version(root), "0.1.0")
            for name in ("Cargo.toml", "bindings/python/Cargo.toml"):
                (root / name).write_text('[package]\nversion="0.1.1"\n')
                with self.assertRaisesRegex(ValueError, "version_metadata_mismatch"):
                    R.source_version(root)
                (root / name).write_text('[package]\nversion="0.1.0"\n')

    def test_noncanonical_and_prerelease_version_spellings_are_excluded(self):
        for version in ("01.1.0", "0.1.0a1", "v0.1.0", "0.1", "0.1.0+local"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                R.expected_names(version)

    def test_optimized_mode_rejects_mismatched_public_tag_before_git(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "event.json"
            data = event()
            data["ref"] = "refs/tags/v0.1.1"
            payload.write_text(json.dumps(data))
            env = {
                **os.environ,
                **environment(),
                "GITHUB_EVENT_PATH": str(payload),
                "GITHUB_REF": data["ref"],
            }
            result = subprocess.run(
                [sys.executable, "-I", "-O", ROOT / "tools/release_ci.py", "gate"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("publication_gate_rejected", result.stderr)

    def test_manual_private_run_outputs_build_only_even_when_protected(self):
        with tempfile.TemporaryDirectory() as directory:
            payload, output = Path(directory) / "event.json", Path(directory) / "output"
            payload.write_text(json.dumps(event()))
            env = {
                **os.environ,
                **environment(),
                "GITHUB_EVENT_PATH": str(payload),
                "GITHUB_OUTPUT": str(output),
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_REPOSITORY": "example/private-project",
            }
            subprocess.run(
                [sys.executable, "-I", "-O", ROOT / "tools/release_ci.py", "gate"],
                env=env,
                check=True,
                capture_output=True,
            )
            self.assertEqual(output.read_text(), "publish=false\nversion=0.1.0\n")


class HistoryTests(unittest.TestCase):
    def test_tag_checkout_and_main_ancestry_with_real_local_git(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = {
                **os.environ,
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_AUTHOR_NAME": "Synthetic fixture",
                "GIT_COMMITTER_NAME": "Synthetic fixture",
                "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            }

            def git(*args):
                return subprocess.check_output(
                    ["git", "-C", str(root), *args], env=env, text=True
                ).strip()

            git("init", "-q")
            tree = git("mktree")
            first = git("commit-tree", tree, "-m", "ordinary fixture")
            other = git("commit-tree", tree, "-m", "separate fixture")
            git("update-ref", "HEAD", first)
            git("update-ref", "refs/remotes/origin/main", first)
            git("tag", "v0.1.0", first)
            R.verify_history(root, first, "refs/tags/v0.1.0")
            with self.assertRaisesRegex(ValueError, "checkout_sha_mismatch"):
                R.verify_history(root, other, "refs/tags/v0.1.0")
            git("tag", "-f", "v0.1.0", other)
            with self.assertRaisesRegex(ValueError, "tag_sha_mismatch"):
                R.verify_history(root, first, "refs/tags/v0.1.0")
            git("tag", "-f", "v0.1.0", first)
            git("update-ref", "refs/remotes/origin/main", other)
            with self.assertRaises(subprocess.CalledProcessError):
                R.verify_history(root, first, "refs/tags/v0.1.0")


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        (self.root / "licenses").mkdir()
        for name in ("LICENSE", "NOTICE", "licenses/dpkt.txt"):
            (self.root / name).write_bytes(b"benign synthetic legal fixture\n")
        self.names = R.expected_names("0.1.0")
        for cp in self.names:
            self.wheel(cp)

    def wheel(self, cp, *, tag=None, legal=b"benign synthetic legal fixture\n"):
        prefix = "octetrail-0.1.0.dist-info/"
        with zipfile.ZipFile(self.dist / self.names[cp], "w") as archive:
            archive.writestr(prefix + "METADATA", "Name: octetrail\nVersion: 0.1.0\n")
            archive.writestr(
                prefix + "WHEEL", f"Tag: {tag or cp + '-' + cp + '-manylinux_2_34_x86_64'}\n"
            )
            for name in ("LICENSE", "NOTICE", "licenses/dpkt.txt"):
                archive.writestr(prefix + "licenses/" + name, legal)

    def test_exact_two_wheels_legal_bytes_tags_and_hashes(self):
        hashes = R.validate_wheels(self.dist, self.root, "0.1.0")
        self.assertEqual(
            hashes,
            {
                cp: hashlib.sha256((self.dist / name).read_bytes()).hexdigest()
                for cp, name in self.names.items()
            },
        )

    def test_extra_sdist_and_missing_wheel_are_rejected(self):
        extra = self.dist / "octetrail-0.1.0.tar.gz"
        extra.write_bytes(b"not a release artifact")
        with self.assertRaisesRegex(ValueError, "wheel_inventory"):
            R.validate_wheels(self.dist, self.root, "0.1.0")
        extra.unlink()
        (self.dist / self.names["cp313"]).unlink()
        with self.assertRaisesRegex(ValueError, "wheel_inventory"):
            R.validate_wheels(self.dist, self.root, "0.1.0")

    def test_wrong_abi_platform_tag_and_changed_license_are_rejected(self):
        self.wheel("cp312", tag="cp312-cp312-manylinux_2_17_x86_64")
        with self.assertRaisesRegex(ValueError, "wheel_tag"):
            R.validate_wheels(self.dist, self.root, "0.1.0")
        self.wheel("cp312", legal=b"changed fixture")
        with self.assertRaisesRegex(ValueError, "wheel_legal_bytes"):
            R.validate_wheels(self.dist, self.root, "0.1.0")


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = yaml.load(
            (ROOT / ".github/workflows/release.yml").read_text(), Loader=yaml.BaseLoader
        )

    def test_triggers_permissions_environment_and_pinned_actions(self):
        workflow = self.workflow
        self.assertEqual(set(workflow["on"]), {"pull_request", "push", "workflow_dispatch"})
        self.assertEqual(workflow["on"]["push"], {"branches": ["main"], "tags": ["v*"]})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(set(workflow["jobs"]), {"build", "release"})
        build, publish = workflow["jobs"]["build"], workflow["jobs"]["release"]
        self.assertEqual(build["permissions"], {"contents": "read"})
        self.assertEqual(publish["permissions"], {"contents": "write"})
        self.assertEqual(publish["environment"]["name"], "github-release")
        self.assertEqual(publish["needs"], "build")
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    self.assertRegex(step["uses"], r"^[A-Za-z0-9_/-]+@[0-9a-f]{40}$")
        self.assertFalse(any("secrets" in str(j) for j in workflow["jobs"].values()))
        self.assertFalse(any("checkout" in s.get("uses", "") for s in publish["steps"]))
        self.assertFalse(
            any("id-token" in j.get("permissions", {}) for j in workflow["jobs"].values())
        )
        self.assertFalse(
            any(
                "pypi-publish" in s.get("uses", "")
                for j in workflow["jobs"].values()
                for s in j["steps"]
            )
        )
        self.assertEqual(publish["steps"][2]["env"]["GH_TOKEN"], "${{ github.token }}")
        for step in publish["steps"]:
            self.assertNotIn("tools/", step.get("run", ""))
            self.assertNotIn("pip install", step.get("run", ""))
        self.assertEqual(
            publish["steps"][0]["with"]["artifact-ids"], "${{ needs.build.outputs.artifact-id }}"
        )

    def test_actual_job_guard_rejects_private_forks_prs_manual_and_unprotected(self):
        context = {
            "github": {
                "event_name": "push",
                "repository": R.CANONICAL,
                "event": event(),
                "ref_type": "tag",
                "ref_protected": True,
                "run_attempt": 1,
            },
            "needs": {"build": {"result": "success", "outputs": {"publish": "true"}}},
            "vars": {"WHEEL_RELEASES_ENABLED": "true"},
        }
        guard = self.workflow["jobs"]["release"]["if"]
        self.assertTrue(evaluate_guard(guard, context))
        retried = copy.deepcopy(context)
        retried["github"]["run_attempt"] = 2
        self.assertTrue(evaluate_guard(guard, retried))
        changes = [
            ("event_name", "pull_request"),
            ("event_name", "workflow_dispatch"),
            ("repository", "example/private-project"),
            ("repository", "example/octetrail"),
            ("ref_type", "branch"),
            ("ref_protected", False),
        ]
        for key, value in changes:
            ctx = copy.deepcopy(context)
            ctx["github"][key] = value
            self.assertFalse(evaluate_guard(guard, ctx))
        ctx = copy.deepcopy(context)
        ctx["github"]["event"]["repository"]["private"] = True
        self.assertFalse(evaluate_guard(guard, ctx))
        ctx = copy.deepcopy(context)
        ctx["needs"]["build"]["outputs"]["publish"] = "false"
        self.assertFalse(evaluate_guard(guard, ctx))
        ctx = copy.deepcopy(context)
        ctx["vars"]["WHEEL_RELEASES_ENABLED"] = ""
        self.assertFalse(evaluate_guard(guard, ctx))
        for name, value in (("default_branch", "other"), ("id", 123)):
            ctx = copy.deepcopy(context)
            ctx["github"]["event"]["repository"][name] = value
            self.assertFalse(evaluate_guard(guard, ctx))
        for name in ("created", "deleted", "forced"):
            ctx = copy.deepcopy(context)
            ctx["github"]["event"][name] = name != "created"
            self.assertFalse(evaluate_guard(guard, ctx))
        for value in ("failure", "cancelled", "skipped"):
            ctx = copy.deepcopy(context)
            ctx["needs"]["build"]["result"] = value
            self.assertFalse(evaluate_guard(guard, ctx))

    def test_publish_job_hash_check_runs_without_checkout_or_oidc(self):
        step = self.workflow["jobs"]["release"]["steps"][1]
        script = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "dist").mkdir()
            env = {**os.environ, "VERSION": "0.1.0"}
            for cp, name in R.expected_names("0.1.0").items():
                payload = b"ordinary local artifact fixture " + cp.encode()
                (root / "dist" / name).write_bytes(payload)
                env[cp.upper() + "_SHA256"] = hashlib.sha256(payload).hexdigest()
            command = [sys.executable, "-I", "-c", script]
            subprocess.run(command, cwd=root, env=env, check=True, capture_output=True)
            env["CP312_SHA256"] = "0" * 64
            result = subprocess.run(command, cwd=root, env=env, check=False, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"wheel_hash_mismatch", result.stderr)


class VersionedWheelCheckTests(unittest.TestCase):
    def fixture(self, path, version="1.2.3", *, wrong_record=False):
        prefix = f"octetrail-{version}.dist-info/"
        files = {
            "octetrail/capture.py": b"# synthetic package fixture\n",
            prefix + "METADATA": f"Name: octetrail\nVersion: {version}\n".encode(),
            prefix + "licenses/LICENSE": b"legal fixture",
            prefix + "licenses/NOTICE": b"notice fixture",
            prefix + "licenses/licenses/dpkt.txt": b"attribution fixture",
            prefix + "licenses/licenses/rust/pyo3-0.30.1-LICENSE-MIT.txt": b"MIT fixture",
            prefix + "licenses/licenses/rust/LICENSE-UNICODE.txt": b"Unicode fixture",
        }
        record = prefix + "RECORD"
        text = io.StringIO(newline="")
        writer = csv.writer(text, lineterminator="\n")
        for name, data in files.items():
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            writer.writerow((name, "sha256=" + ("wrong" if wrong_record else digest), len(data)))
        writer.writerow((record, "", ""))
        files[record] = text.getvalue().encode()
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)

    def test_expected_version_is_derived_from_source_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "ordinary.whl"
            self.fixture(path)
            (root / "pyproject.toml").write_text('[project]\nversion="1.2.3"\n')
            with mock.patch.object(C, "ROOT", root):
                C.check(path)

    def test_wrong_version_and_record_still_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ordinary.whl"
            self.fixture(path)
            with self.assertRaises(ValueError):
                C.check(path, "1.2.4")
            self.fixture(path, wrong_record=True)
            with self.assertRaises(ValueError):
                C.check(path, "1.2.3")

    def test_optimized_cli_cannot_skip_wheel_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ordinary.whl"
            self.fixture(path)
            result = subprocess.run(
                [sys.executable, "-I", "-O", ROOT / "tools/check_wheel.py", path],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
