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
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import yaml
from release_fixture import NAMES, make_release, write_manifest

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
        if term.strip() == "!cancelled()":
            results.append(not context.get("cancelled", False))
            continue
        operator = " != " if " != " in term else " == "
        field, literal = term.strip().split(operator)
        value = context
        for name in field.split("."):
            value = value[name]
        expected = {"true": True, "false": False}.get(literal)
        if expected is None:
            expected = ast.literal_eval(literal)
        equal = type(value) is type(expected) and value == expected
        results.append(equal if operator == " == " else not equal)
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
            self.assertEqual(
                output.read_text(), f"publish=false\nversion={R.source_version(ROOT)}\n"
            )


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
    LEGAL = b"benign synthetic legal fixture\n"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        (self.root / "licenses").mkdir()
        for name in ("LICENSE", "NOTICE", "licenses/dpkt.txt"):
            (self.root / name).write_bytes(self.LEGAL)
        (self.root / "Cargo.lock").write_bytes(b"lock fixture\n")
        (self.root / "pyproject.toml").write_bytes(b"project fixture\n")
        self.names = R.expected_names("0.1.0")
        for key in R.PLATFORMS:
            self.wheel(key)
        self.sdist()

    def wheel(self, key, *, tags=None, legal=LEGAL):
        prefix = "octetrail-0.1.0.dist-info/"
        tags = tags or [R.ABI + "-" + t for t in R.PLATFORMS[key].split(".")]
        with zipfile.ZipFile(self.dist / self.names[key], "w") as archive:
            archive.writestr(prefix + "METADATA", "Name: octetrail\nVersion: 0.1.0\n")
            archive.writestr(prefix + "WHEEL", "".join(f"Tag: {t}\n" for t in tags))
            for name in ("LICENSE", "NOTICE", "licenses/dpkt.txt"):
                archive.writestr(prefix + "licenses/" + name, legal)

    def sdist(self, *, extra=None, lock=None):
        top = "octetrail-0.1.0/"
        files = {
            "PKG-INFO": b"Name: octetrail\nVersion: 0.1.0\n",
            "Cargo.lock": lock or b"lock fixture\n",
            "pyproject.toml": b"project fixture\n",
            "LICENSE": self.LEGAL,
            "NOTICE": self.LEGAL,
            "licenses/dpkt.txt": self.LEGAL,
            **(extra or {}),
        }
        with tarfile.open(self.dist / self.names["sdist"], "w:gz") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(top + name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

    def test_every_platform_wheel_and_sdist_with_hashes(self):
        hashes = R.validate_dist(self.dist, self.root, "0.1.0")
        self.assertEqual(len(hashes), 9)
        self.assertEqual(
            hashes,
            {
                name: hashlib.sha256((self.dist / name).read_bytes()).hexdigest()
                for name in self.names.values()
            },
        )
        text = R.manifest_text(hashes)
        self.assertEqual(len(text.splitlines()), 9)
        self.assertTrue(all(len(line.split("  ")[0]) == 64 for line in text.splitlines()))

    def test_names_cover_each_platform_with_the_stable_abi(self):
        names = R.expected_names("1.2.3")
        self.assertEqual(names["sdist"], "octetrail-1.2.3.tar.gz")
        self.assertEqual(names["windows-arm64"], "octetrail-1.2.3-cp310-abi3-win_arm64.whl")
        self.assertEqual(len(set(names.values())), 9)
        with self.assertRaisesRegex(ValueError, "version_format"):
            R.expected_names("1.2.3rc1")

    def test_extra_and_missing_files_are_rejected(self):
        extra = self.dist / "octetrail-0.1.0-cp312-cp312-manylinux_2_34_x86_64.whl"
        extra.write_bytes(b"not a release artifact")
        with self.assertRaisesRegex(ValueError, "dist_inventory"):
            R.validate_dist(self.dist, self.root, "0.1.0")
        extra.unlink()
        (self.dist / self.names["macos-arm64"]).unlink()
        with self.assertRaisesRegex(ValueError, "dist_inventory"):
            R.validate_dist(self.dist, self.root, "0.1.0")

    def test_inventory_demands_every_wheel_and_the_sdist(self):
        # The build job may run after the macOS arm64 fallback, so this check is
        # what stops a release with a wheel missing from any other leg.
        self.assertEqual(len(self.names), 9)
        self.assertEqual(sum(n.endswith(".whl") for n in self.names.values()), 8)
        for key, name in self.names.items():
            path = self.dist / name
            data = path.read_bytes()
            path.unlink()
            with self.subTest(missing=key), self.assertRaisesRegex(ValueError, "dist_inventory"):
                R.validate_dist(self.dist, self.root, "0.1.0")
            path.write_bytes(data)
        self.assertEqual(len(R.validate_dist(self.dist, self.root, "0.1.0")), 9)

    def test_wrong_platform_tag_and_changed_license_are_rejected(self):
        self.wheel("linux-x86_64", tags=["cp310-abi3-manylinux_2_34_x86_64"])
        with self.assertRaisesRegex(ValueError, "wheel_tag"):
            R.validate_dist(self.dist, self.root, "0.1.0")
        self.wheel("linux-x86_64", legal=b"changed fixture")
        with self.assertRaisesRegex(ValueError, "wheel_legal_bytes"):
            R.validate_dist(self.dist, self.root, "0.1.0")

    def test_sdist_private_paths_and_changed_inputs_are_rejected(self):
        self.sdist(extra={".github/workflows/release.yml": b"x"})
        with self.assertRaisesRegex(ValueError, "sdist_private_path"):
            R.validate_dist(self.dist, self.root, "0.1.0")
        self.sdist(lock=b"different lock\n")
        with self.assertRaisesRegex(ValueError, "sdist_bytes"):
            R.validate_dist(self.dist, self.root, "0.1.0")


class ReleaseNotesTests(unittest.TestCase):
    def test_each_section_lists_an_entry_once(self):
        text = (ROOT / "docs/release-notes.md").read_text()
        sections = text.split("\n## ")[1:]
        self.assertTrue(sections)
        for section in sections:
            title, _, body = section.partition("\n")
            heads = [
                para.split("\n")[0]
                for para in body.strip("\n").split("\n\n")
                if para and not para.startswith(("- ", "  "))
            ]
            with self.subTest(section=title):
                repeated = sorted({h for h in heads if heads.count(h) > 1})
                self.assertEqual(repeated, [])


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = yaml.load(
            (ROOT / ".github/workflows/release.yml").read_text(), Loader=yaml.BaseLoader
        )

    def test_triggers_permissions_environment_and_pinned_actions(self):
        workflow = self.workflow
        self.assertEqual(set(workflow["on"]), {"pull_request", "push", "workflow_dispatch"})
        self.assertEqual(workflow["on"]["push"], {"branches": ["main", "ci/**"], "tags": ["v*"]})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(
            set(workflow["jobs"]),
            {
                "gate",
                "check",
                "wheels",
                "macos-arm64-missing",
                "wheels-macos-arm64-fallback",
                "sdist",
                "build",
                "release",
                "pypi",
            },
        )
        self.assertEqual(
            workflow["jobs"]["build"]["needs"],
            ["gate", "check", "wheels", "wheels-macos-arm64-fallback", "sdist"],
        )
        for name in (
            "gate",
            "check",
            "wheels",
            "wheels-macos-arm64-fallback",
            "sdist",
            "build",
        ):
            self.assertEqual(workflow["jobs"][name]["permissions"], {"contents": "read"})
        # Only the fallback probe reads the run's jobs, to see whether a runner was assigned.
        self.assertEqual(
            workflow["jobs"]["macos-arm64-missing"]["permissions"],
            {"actions": "read", "contents": "read"},
        )
        matrix = {
            row["name"] for row in workflow["jobs"]["wheels"]["strategy"]["matrix"]["include"]
        }
        self.assertEqual(matrix, set(R.PLATFORMS))
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
        self.assertEqual(
            [
                name
                for name, job in workflow["jobs"].items()
                if "id-token" in job.get("permissions", {})
            ],
            ["pypi"],
        )
        self.assertFalse(any("pypi-publish" in step.get("uses", "") for step in publish["steps"]))
        self.assertEqual(publish["steps"][2]["env"]["GH_TOKEN"], "${{ github.token }}")
        for step in publish["steps"]:
            self.assertNotIn("tools/", step.get("run", ""))
            self.assertNotIn("pip install", step.get("run", ""))
        self.assertEqual(
            publish["steps"][0]["with"],
            {"artifact-ids": "${{ needs.build.outputs.artifact-id }}", "path": "release"},
        )

    def test_macos_arm64_fallback_repeats_the_wheel_steps_on_macos_14(self):
        jobs = self.workflow["jobs"]
        primary, fallback = jobs["wheels"], jobs["wheels-macos-arm64-fallback"]
        self.assertEqual(fallback["steps"], primary["steps"])
        for key in ("runs-on", "timeout-minutes", "permissions", "defaults"):
            self.assertEqual(fallback[key], primary[key])
        [row] = fallback["strategy"]["matrix"]["include"]
        [arm] = [r for r in primary["strategy"]["matrix"]["include"] if r["name"] == "macos-arm64"]
        self.assertEqual({**arm, "os": "macos-14", "compatibility": "", "zig": "false"}, row)
        self.assertNotIn("zig", arm)
        self.assertNotIn("compatibility", arm)
        self.assertEqual(arm["os"], "macos-15")
        self.assertEqual(fallback["needs"], "macos-arm64-missing")
        self.assertEqual(
            fallback["if"],
            "${{ !cancelled() && needs.macos-arm64-missing.outputs.missing == 'true' }}",
        )
        probe = jobs["macos-arm64-missing"]
        self.assertEqual(probe["needs"], "wheels")
        self.assertEqual(probe["if"], "${{ !cancelled() && needs.wheels.result == 'failure' }}")
        self.assertEqual(probe["permissions"], {"actions": "read", "contents": "read"})
        step = probe["steps"][-1]
        self.assertEqual(step["run"], '"$BUILD_PY" -B -I tools/release_ci.py fallback')
        self.assertEqual(step["env"]["GH_TOKEN"], "${{ github.token }}")
        self.assertEqual(
            probe["outputs"]["missing"], "${{ steps." + step["id"] + ".outputs.missing }}"
        )
        self.assertEqual(R.FALLBACK_JOB, "Wheel " + arm["name"])
        self.assertEqual(primary["name"], "Wheel ${{ matrix.name }}")

    def test_fallback_runs_only_when_the_macos_arm64_runner_was_not_acquired(self):
        def job(**fields):
            return {
                "name": R.FALLBACK_JOB,
                "conclusion": "failure",
                "runner_name": "",
                "steps": [],
                **fields,
            }

        other = {
            "name": "Wheel linux-x86_64",
            "conclusion": "success",
            "runner_name": "r",
            "steps": [],
        }
        ran = {"name": "Set up job", "status": "completed", "conclusion": "success"}
        failed = {"name": "Test the wheel", "status": "completed", "conclusion": "failure"}
        self.assertTrue(R.runner_not_acquired([other, job()]))
        self.assertTrue(R.runner_not_acquired([job(runner_name=None, steps=None)]))
        self.assertTrue(
            R.runner_not_acquired([job(steps=[{"name": "Set up job", "status": "queued"}])])
        )
        for case in (
            job(runner_name="GitHub Actions 12", steps=[ran, failed]),
            job(steps=[ran, failed]),
            job(runner_name="GitHub Actions 12"),
            job(conclusion="success"),
            job(conclusion="cancelled"),
        ):
            with self.subTest(case=case):
                self.assertFalse(R.runner_not_acquired([other, case]))
        self.assertFalse(R.runner_not_acquired([other]))
        self.assertFalse(R.runner_not_acquired([job(), job()]))

    def test_fallback_reads_every_page_of_the_run_attempt_jobs(self):
        pages = [
            {"total_count": 3, "jobs": [{"name": "a"}, {"name": "b"}]},
            {"total_count": 3, "jobs": [{"name": R.FALLBACK_JOB}]},
        ]
        seen = []

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def opener(request, timeout):
            seen.append((request.full_url, request.get_header("Authorization"), timeout))
            return Response(json.dumps(pages[len(seen) - 1]).encode())

        env = {
            "GITHUB_API_URL": "https://api.example",
            "GITHUB_REPOSITORY": "o/r",
            "GITHUB_RUN_ID": "7",
            "GITHUB_RUN_ATTEMPT": "2",
            "GH_TOKEN": "t",
        }
        jobs = R.run_jobs(env, opener=opener)
        self.assertEqual([j["name"] for j in jobs], ["a", "b", R.FALLBACK_JOB])
        base = "https://api.example/repos/o/r/actions/runs/7/attempts/2/jobs?per_page=100"
        self.assertEqual(
            seen, [(base + "&page=1", "Bearer t", 30), (base + "&page=2", "Bearer t", 30)]
        )

    def test_build_runs_after_the_full_matrix_or_the_macos_arm64_fallback(self):
        guard = self.workflow["jobs"]["build"]["if"]

        def boolean(node):
            # Only and, or, == and literals: the shape of the workflow guard.
            if isinstance(node, ast.BoolOp):
                values = [boolean(v) for v in node.values]
                return all(values) if isinstance(node.op, ast.And) else any(values)
            if isinstance(node, ast.Compare) and isinstance(node.ops[0], ast.Eq):
                return node.left.value == node.comparators[0].value
            if isinstance(node, ast.Constant) and isinstance(node.value, bool):
                return node.value
            raise ValueError(ast.dump(node))

        def runs(cancelled=False, **results):
            state = {"gate": "success", "check": "success", "sdist": "success"}
            state.update({"wheels": "success", "wheels-macos-arm64-fallback": "skipped"})
            state.update({k.replace("_", "-"): v for k, v in results.items()})
            expression = guard.replace("&&", " and ").replace("||", " or ")
            expression = expression.replace("!cancelled()", str(not cancelled))
            for name, value in state.items():
                expression = expression.replace("needs.%s.result" % name, repr(value))
            return boolean(ast.parse(expression, mode="eval").body)

        self.assertTrue(runs())
        self.assertTrue(runs(wheels="failure", wheels_macos_arm64_fallback="success"))
        self.assertFalse(runs(wheels="failure"))
        self.assertFalse(runs(wheels="failure", wheels_macos_arm64_fallback="failure"))
        self.assertFalse(runs(cancelled=True))
        for job in ("gate", "check", "sdist"):
            self.assertFalse(runs(**{job: "failure"}))
            self.assertFalse(
                runs(
                    **{
                        job: "failure",
                        "wheels": "failure",
                        "wheels_macos_arm64_fallback": "success",
                    }
                )
            )
        # Publishing still needs a successful build, and PyPI still needs the first attempt.
        for job in ("release", "pypi"):
            self.assertTrue(self.workflow["jobs"][job]["if"].startswith("!cancelled() && "))
        self.assertIn("needs.build.result == 'success'", self.workflow["jobs"]["release"]["if"])
        self.assertIn("github.run_attempt == 1", self.workflow["jobs"]["pypi"]["if"])

    def test_jobs_with_needs_use_a_status_function(self):
        # Without one, GitHub adds success(), which is false when any upstream
        # job was skipped, such as the macOS arm64 fallback on a normal run.
        status = re.compile(r"(?<![\w.])(!?cancelled|always|success|failure)\(\)")
        for name, job in self.workflow["jobs"].items():
            if job.get("needs"):
                with self.subTest(job=name):
                    self.assertRegex(str(job.get("if", "")), status)

    def test_publish_guards_pass_a_successful_build_and_stop_on_cancel(self):
        context = {
            "github": {
                "event_name": "push",
                "repository": R.CANONICAL,
                "event": event(),
                "ref_type": "tag",
                "ref_protected": True,
                "run_attempt": 1,
            },
            "needs": {
                "build": {"result": "success", "outputs": {"publish": "true", "artifact-id": "1"}}
            },
            "vars": {"WHEEL_RELEASES_ENABLED": "true", "PYPI_PUBLISHING_ENABLED": "true"},
        }
        for job in ("release", "pypi"):
            guard = self.workflow["jobs"][job]["if"]
            with self.subTest(job=job):
                self.assertTrue(evaluate_guard(guard, context))
                self.assertFalse(evaluate_guard(guard, {**context, "cancelled": True}))

    def test_inline_platform_lists_match_the_release_tooling(self):
        expected = repr(tuple(R.PLATFORMS.values()))
        scripts = [
            self.workflow["jobs"]["release"]["steps"][1]["run"],
            self.workflow["jobs"]["release"]["steps"][2]["run"],
            self.workflow["jobs"]["pypi"]["steps"][2]["run"],
        ]
        for script in scripts:
            self.assertIn("platforms = " + expected.replace("'", '"'), script)
            self.assertIn(R.ABI, script)

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
            env = {**os.environ, "VERSION": "0.1.0", "MANIFEST_SHA256": make_release(root)}
            command = [sys.executable, "-I", "-c", script]
            subprocess.run(command, cwd=root, env=env, check=True, capture_output=True)
            env["MANIFEST_SHA256"] = "0" * 64
            result = subprocess.run(command, cwd=root, env=env, check=False, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"manifest_hash_mismatch", result.stderr)
            env["MANIFEST_SHA256"] = write_manifest(root)
            (root / "release/dist" / NAMES[0]).write_bytes(b"changed")
            result = subprocess.run(command, cwd=root, env=env, check=False, capture_output=True)
            self.assertIn(b"dist_hash_mismatch", result.stderr)


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
