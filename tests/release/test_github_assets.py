"""Execute the workflow's publisher only against a local fake gh, never a service."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

import yaml
from release_fixture import ASSETS, NAMES, make_release, write_manifest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = yaml.load((ROOT / ".github/workflows/release.yml").read_text(), Loader=yaml.BaseLoader)
SCRIPT = WORKFLOW["jobs"]["release"]["steps"][2]["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
REPO = "Defense-Exploration-Holdings/octetrail"
SHA = "1" * 40

# This executable has no network implementation. Unknown CLI operations fail.
FAKE = textwrap.dedent("""\
import hashlib, json, os, sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs
root=Path(os.environ['MODEL_ROOT']); state_path=root/'state.json'
s=json.loads(state_path.read_text()); mode=os.environ['MODEL_MODE']; args=sys.argv[1:]
if args[:4]!=['api','--hostname','github.com','--method']: raise SystemExit('unexpected CLI')
method, endpoint=args[4:6]; s['calls'].append([method,endpoint])
repo='Defense-Exploration-Holdings/octetrail'; base='repos/'+repo; tag='v0.1.0'; sha='1'*40
def finish(value):
    state_path.write_text(json.dumps(s)); print(json.dumps(value)); raise SystemExit(0)
def fail():
    state_path.write_text(json.dumps(s)); raise SystemExit('synthetic API failure')
if endpoint==base+'/releases?per_page=100' and method=='GET':
    if mode=='listing-error': fail()
    rows=[]
    if mode in ('existing-draft','existing-published'):
        rows=[{'id':9,'tag_name':tag,'draft':mode=='existing-draft'}]
    if s['created']:
        rows=[s['release']]
        if mode=='creation-race': rows.append({'id':9,'tag_name':tag,'draft':True})
        if mode=='foreign-author': rows=[dict(s['release'],author={'login':'another-user'})]
    finish([rows])
if endpoint==base+'/git/ref/tags/'+tag and method=='GET':
    if mode=='missing-tag': fail()
    finish({'object':{'type':'tag' if mode=='annotated' else 'commit','sha':'2'*40 if mode=='annotated' else ('3'*40 if mode=='moved-tag' else sha)}})
if endpoint==base+'/git/tags/'+'2'*40 and method=='GET': finish({'object':{'type':'commit','sha':sha}})
if endpoint==base+'/compare/'+sha+'...main' and method=='GET':
    finish({'status':'behind' if mode=='unrelated-main' else 'ahead','merge_base_commit':{'sha':'3'*40 if mode=='unrelated-main' else sha}})
if endpoint==base+'/releases' and method=='POST':
    body=json.load(sys.stdin)
    if body['draft'] is not True or body['prerelease'] is not False or body['target_commitish']!=sha or body['tag_name']!=tag: raise SystemExit('wrong create body')
    s['created']=True; s['release']={'id':7,'tag_name':tag,'draft':True,'prerelease':False,'assets':[],'body':body['body'],'target_commitish':sha,'author':{'login':'github-actions[bot]'}}
    finish(s['release'])
if endpoint.startswith('https://uploads.github.com/repos/'+repo+'/releases/7/assets?name=') and method=='POST':
    if mode=='upload-error' or (mode=='after-first-upload-error' and len(s['release']['assets'])==1): fail()
    name=parse_qs(urlparse(endpoint).query)['name'][0]; path=Path(args[args.index('--input')+1]); data=path.read_bytes()
    asset={'name':name,'state':'uploaded','size':len(data),'digest':'sha256:'+hashlib.sha256(data).hexdigest()}
    if mode=='digest-mismatch': asset['digest']='sha256:'+'0'*64
    s['release']['assets'].append(asset); finish(asset)
if endpoint==base+'/releases/7/assets?per_page=100' and method=='GET':
    assets=s['release']['assets']
    if mode=='extra-asset': assets=assets+[{'name':'extra.whl'}]
    if mode=='existing-digest-mismatch' and assets:
        assets=[dict(a,digest='sha256:'+'0'*64) for a in assets]
    if mode=='unfinished-asset' and assets:
        assets=[dict(a,state='starter') for a in assets]
    finish([assets])
if endpoint==base+'/releases/7' and method=='GET':
    if mode=='before-publish-error' and len(s['release']['assets'])==int(os.environ['MODEL_ASSETS']): fail()
    if mode=='draft-changed': s['release']['draft']=False
    finish(s['release'])
if endpoint==base+'/releases/7' and method=='PATCH':
    body=json.load(sys.stdin)
    if body!={'draft':False,'prerelease':False,'make_latest':'true'}: raise SystemExit('wrong publish body')
    s['published']=True; s['release']['draft']=False; finish(s['release'])
raise SystemExit('unrecognized synthetic request')
""")


class GitHubAssetTests(unittest.TestCase):
    def model(
        self,
        mode="normal",
        *,
        changes=None,
        extra=False,
        changed=False,
        optimized=False,
        resume=False,
        resume_mode="after-first-upload-error",
        resume_changes=None,
        resume_changed=False,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            executable = root / "bin/gh"
            executable.write_text("#!" + sys.executable + "\n" + FAKE)
            executable.chmod(0o755)
            env = {
                key: value
                for key, value in os.environ.items()
                if key not in ("GH_TOKEN", "GITHUB_TOKEN")
            }
            env.update(
                PATH=str(root / "bin") + os.pathsep + env["PATH"],
                MODEL_ROOT=str(root),
                MODEL_MODE=mode,
                VERSION="0.1.0",
                RELEASE_TAG="v0.1.0",
                SOURCE_SHA=SHA,
                RUN_ID="42",
                ARTIFACT_ID="77",
                REPOSITORY=REPO,
                REPOSITORY_ID="1457516742",
            )
            self.assertEqual(shutil.which("gh", path=env["PATH"]), str(executable))
            env["MANIFEST_SHA256"] = make_release(root)
            env["MODEL_ASSETS"] = str(len(ASSETS))
            if changed:
                (root / "release/dist" / NAMES[0]).write_bytes(b"changed fixture")
            if extra:
                (root / "release/dist/ordinary.tar.gz").write_bytes(b"unexpected extra file")
            env.update(changes or {})
            state = {"calls": [], "created": False, "published": False}
            (root / "state.json").write_text(json.dumps(state))
            command = [sys.executable, "-B", "-I", *(["-O"] if optimized else []), "-c", SCRIPT]
            if resume:
                env["MODEL_MODE"] = resume_mode
                first = subprocess.run(
                    command,
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
                self.assertNotEqual(first.returncode, 0)
                state = json.loads((root / "state.json").read_text())
                self.assertTrue(state["created"])
                self.assertFalse(state["published"])
                state["resume_call_offset"] = len(state["calls"])
                (root / "state.json").write_text(json.dumps(state))
                env.update(resume_changes or {})
                if resume_changed:
                    (root / "release/dist" / NAMES[0]).write_bytes(b"different artifact")
                    env["MANIFEST_SHA256"] = write_manifest(root)
                env["MODEL_MODE"] = mode
            result = subprocess.run(
                command, cwd=root, env=env, text=True, capture_output=True, check=False, timeout=30
            )
            return result, json.loads((root / "state.json").read_text())

    def test_new_release_publishes_only_after_every_exact_asset(self):
        for mode in ("normal", "annotated"):
            result, state = self.model(mode)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(state["published"])
            self.assertEqual({a["name"] for a in state["release"]["assets"]}, set(ASSETS))
            writes = [(method, endpoint) for method, endpoint in state["calls"] if method != "GET"]
            self.assertEqual([m for m, _ in writes], ["POST"] * (1 + len(ASSETS)) + ["PATCH"])
            self.assertTrue(writes[-1][1].endswith("/releases/7"))

    def test_existing_draft_published_or_unreadable_listing_never_writes(self):
        for mode in ("existing-draft", "existing-published", "listing-error"):
            result, state = self.model(mode)
            self.assertNotEqual(result.returncode, 0, mode)
            self.assertFalse(state["created"])
            self.assertTrue(all(method == "GET" for method, _ in state["calls"]))

    def test_missing_moved_or_non_main_tag_never_creates_a_release(self):
        for mode in ("missing-tag", "moved-tag", "unrelated-main"):
            result, state = self.model(mode)
            self.assertNotEqual(result.returncode, 0, mode)
            self.assertFalse(state["created"])
            self.assertTrue(all(method == "GET" for method, _ in state["calls"]))

    def test_upload_or_state_failures_do_not_publish_or_remove_the_draft(self):
        for mode in (
            "upload-error",
            "digest-mismatch",
            "extra-asset",
            "creation-race",
            "draft-changed",
        ):
            result, state = self.model(mode)
            self.assertNotEqual(result.returncode, 0, mode)
            self.assertTrue(state["created"])
            self.assertFalse(state["published"])
            self.assertFalse(any(method in ("PATCH", "DELETE") for method, _ in state["calls"]))

    def test_local_version_identity_or_artifact_rejections_make_no_api_calls(self):
        for kwargs in (
            {"changes": {"VERSION": "0.1.0a1"}},
            {"changes": {"RELEASE_TAG": "v0.2.0"}},
            {"changes": {"SOURCE_SHA": "branch"}},
            {"changes": {"REPOSITORY": "example/octetrail"}},
            {"changes": {"REPOSITORY_ID": "123"}},
            {"extra": True},
            {"changed": True},
        ):
            result, state = self.model(**kwargs)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(state["calls"], [])

    def test_optimized_inline_code_retains_positive_and_negative_controls(self):
        result, state = self.model(optimized=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(state["published"])
        for mode in ("existing-draft", "moved-tag", "digest-mismatch"):
            result, state = self.model(mode, optimized=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(state["published"])

    def test_same_run_draft_recovery_uploads_only_missing_assets(self):
        result, state = self.model(resume=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(state["published"])
        writes = [(m, p) for m, p in state["calls"][state["resume_call_offset"] :] if m != "GET"]
        self.assertEqual([m for m, _ in writes], ["POST"] * (len(ASSETS) - 1) + ["PATCH"])
        self.assertEqual({a["name"] for a in state["release"]["assets"]}, set(ASSETS))
        result, state = self.model(resume=True, resume_mode="before-publish-error", optimized=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            [m for m, _ in state["calls"][state["resume_call_offset"] :] if m != "GET"], ["PATCH"]
        )

    def test_recovery_rejects_other_runs_artifacts_sources_and_existing_bad_bytes(self):
        for kwargs in (
            {"resume_changes": {"RUN_ID": "43"}},
            {"resume_changes": {"ARTIFACT_ID": "78"}},
            {"resume_changes": {"SOURCE_SHA": "3" * 40}},
            {"resume_changed": True},
            {"mode": "existing-digest-mismatch"},
            {"mode": "extra-asset"},
            {"mode": "foreign-author"},
            {"mode": "unfinished-asset"},
        ):
            result, state = self.model(resume=True, **kwargs)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(state["published"])
            self.assertTrue(
                all(m == "GET" for m, _ in state["calls"][state["resume_call_offset"] :])
            )


if __name__ == "__main__":
    unittest.main()
