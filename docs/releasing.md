# Wheel builds and GitHub Releases

The [workflow](../.github/workflows/release.yml) builds and tests Linux x86-64
CPython 3.12 and 3.13 wheels on updates to `main`, pull requests and manual
dispatch. These build paths have read-only repository permissions. Manual runs,
including ones selecting a tag, cannot upload release assets. No source
distribution is built or uploaded. PyPI publishing has a separate opt-in job,
described below; ordinary builds do not request OIDC tokens.

Rust 1.85.1, locked Cargo dependencies and hash-pinned Python build/validation
tools are used. The build checks formatting, Clippy, native tests, Python tests,
release gates, wheel records, metadata, licenses, strict Twine checks and
auditwheel policy. Both exact wheels are installed into fresh matching
interpreter environments and tested against independent benign capture fixtures
and the two hash-pinned dpkt references. The artifact contains only these tested
wheels and is retained for seven days.

The wheel tag is `manylinux_2_34_x86_64`, with glibc 2.34 as its declared minimum.
Symbol-policy inspection is not execution on every compatible Linux distribution.
The runner is Ubuntu 24.04. No musl, ARM, Windows, macOS, PyPy or other Python
version support is established by this workflow.

## Verify the first build after installation

Installing the workflow on the default `main` branch triggers a build on that
push. A build can also be requested explicitly from `main`:

```sh
gh workflow run release.yml --repo Defense-Exploration-Holdings/octetrail --ref main
gh run list --repo Defense-Exploration-Holdings/octetrail --workflow release.yml
```

Open that run and confirm the build succeeds, contains exactly the two wheel
files, and skips the release job. This works before release activation or tag
creation and does not require PyPI configuration. Inspect/download the build
artifact rather than creating a release to test the installation.

## Deliberate version-tag releases

GitHub Release upload is off unless the repository variable
`WHEEL_RELEASES_ENABLED` is exactly `true`. Administrators must independently
configure and review the following controls before enabling it:

1. Protect `main`, review workflow changes and prohibit force pushes/deletion.
2. Protect tags matching `v*`: restrict creation to release maintainers and
   prohibit updates/deletion. Eligible tags must report `ref_protected=true`.
3. Create the `github-release` environment with required release reviewers,
   prevention of self-review and selected-tag deployment restrictions for `v*`.
   Do not allow branch deployments; disable administrator bypass where available.
4. Allow the pinned actions and the dedicated release job's `contents: write`
   permission under applicable Actions policy. Keep default token permissions
   read-only. No deploy key, personal token or stored release credential is used.
5. Review the successful public build and exact proposed workflow, then
   separately authorize setting `WHEEL_RELEASES_ENABLED=true`.

A release build requires the first attempt of a new, unforced, protected stable
`vX.Y.Z` tag push in the canonical public repository. The tag version must match
`pyproject.toml`, both Cargo manifests and the Python package version. The tag
and checkout must identify the same commit on fetched `main` ancestry. Invalid
public release-tag pushes fail the build. Forks, private repositories, PRs,
branch pushes and manual runs cannot upload through this workflow. A complete
build rerun fails the initial tag gate. A failed release job alone has the narrow
same-run recovery path below.

Choose an unused version, update all version declarations and the lockfile
together, and deliberately tag the reviewed current `main` commit. Approve the
protected environment only after reviewing the successful build and its files.
The `0.2.0` metadata's Alpha classifier is not a prerelease version spelling;
prerelease and local-version tag spellings are excluded.

Only the dedicated release job requests `contents: write`. It downloads the
successful build's immutable artifact ID in the same run and verifies the exact
two filenames and SHA-256 outputs. There is no checkout, package installation or
project execution in this job. Inline standard-library checks invoke the runner's
installed `gh` with the built-in `GITHUB_TOKEN` only.

Before any write, it checks existing releases, including visible drafts, and
rechecks the remote tag commit and `main` ancestry. It creates a new draft,
uploads exactly the two verified wheels, checks the remote asset names, sizes
and SHA-256 digests, then publishes that new release. It never deletes, replaces
or clobbers existing release assets or adopts a foreign release. GitHub's generated source-code archive
links are not uploaded Python source distributions.

Published releases and foreign drafts stop the job. Read/API failures or
mismatches stop before publication. A failure after draft creation can leave an
unpublished draft or partial upload. Inspect the outcome before retrying only the
failed release job, while the original artifact is retained. The successful build
must not be rerun. Recovery requires a GitHub Actions bot-owned draft with an
exact receipt binding the repository, source, version, run ID, immutable artifact
ID, wheel names, sizes and digests. Existing uploaded assets must match exactly;
only absent assets are uploaded. The complete inventory is verified before
publication. Changed artifacts, a different run, edited receipt, unrelated source,
extra assets or mismatched bytes are rejected.

An unfinished upload record (`starter`), mismatched asset, expired artifact or
uncertain publication result needs separate manual investigation and any
separately authorized cleanup. The workflow never deletes or overwrites assets,
retags a version, or edits another release to recover.

This repository content does not configure admin controls, activate uploads,
create tags, perform a release or establish a live service test. The documented
local tests use a fake CLI with no networking. See GitHub's
[token permissions](https://docs.github.com/en/actions/tutorials/authenticate-with-github_token),
[release CLI](https://cli.github.com/manual/gh_release_create) and
[environment protections](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

## Optional PyPI Trusted Publishing

PyPI has its own `pypi` job and opt-in, independent of GitHub Release uploads.
It is off when `PYPI_PUBLISHING_ENABLED` is absent from the effective `vars`
context or does not compare equal to `true`. GitHub string comparisons ignore
case, so `TRUE` also opts in. The context can inherit organization variables;
absence of a repository-level setting alone does not prove the effective value
is empty. Before activation, review the effective configuration and use a
repository-level opt-in. An environment-only value is unavailable when this
job-level gate is evaluated. No live configuration values are inspected or
created by this preparation.
`WHEEL_RELEASES_ENABLED` continues to control only the GitHub Release job.

The PyPI job requires the canonical public repository name and numeric identity,
default branch `main`, an initial unforced protected version-tag push, successful
validated build outputs, a nonempty artifact ID, and the first workflow attempt.
The existing build gate verifies the stable tag against all version declarations,
the checked-out source commit and fetched main history. PRs, branch pushes,
manual runs, other repositories and complete reruns cannot publish. The job does
not depend on completion of the separate GitHub Release job.

Only this job has `id-token: write`. Its other token permissions are unset, and
GitHub treats unspecified permissions as `none` when job permissions are listed.
The build remains read-only. The GitHub Release job keeps its separate
`contents: write` permission and has no OIDC permission.

Before downloading, a stdlib check validates the version/tag, numeric artifact
ID and both expected SHA-256 digests. The download is pinned to that immutable
artifact ID in the same workflow run; it cannot select another run or repository.
The exact two-file wheel inventory and hashes are checked again before the
pinned official PyPA action. Missing, extra, changed or nonregular files stop the
job. There is no checkout, source execution or project installation in the PyPI
job, no stored PyPI token, and no sdist. Attestations and metadata verification
are enabled; existing PyPI filenames are errors rather than silently skipped.

Before any separately approved activation, administrators must configure the
`pypi` GitHub environment with required release review, prevention of self-review
and selected `v*` tag deployments, without branch deployments or administrator
bypass where available. Main and version-tag protections described above must
also be in place. Repository content does not configure or verify these settings.

The PyPI Trusted Publisher fields are owner `Defense-Exploration-Holdings`,
repository `octetrail`, workflow filename `release.yml`, and environment `pypi`.
The filename is not `release.yaml`. Use the existing project settings or a
pending publisher with project name `octetrail` as appropriate. Registration,
public installation, setting the opt-in and creating an unused version tag are
separate reviewed actions. Do not test this preparation with a real publication.
Investigate any uncertain upload outcome before taking further action; no PyPI
recovery or overwrite path is provided.

See the [PyPI Trusted Publishing guide](https://docs.pypi.org/trusted-publishers/using-a-publisher/),
[GitHub permission syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
and [expression comparison rules](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#operators).
