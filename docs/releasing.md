# Releasing

A FastSMTP release involves four distinct artifacts, and **none of them implies the
others**:

- a **git tag** (`vX.Y.Z`), created by the version bump
- a **GitHub release**, published from the draft that Release Drafter maintains
- a set of **container images** on [ghcr.io](https://github.com/jsenecal/fastsmtp/pkgs/container/fastsmtp),
  built by the `Release` workflow
- two **PyPI packages**, [`fastsmtp`](https://pypi.org/project/fastsmtp/) and
  [`fastsmtp-cli`](https://pypi.org/project/fastsmtp-cli/), uploaded by the same
  workflow

Tagging alone builds nothing. Publishing the release is what triggers the image build
and both uploads. And an image can exist without any GitHub release at all (see
[Verify the images on ghcr](#4-verify-the-images-on-ghcr)). Follow the steps below in
order.

## Before anything: label every PR

Release Drafter resolves the next version number from **PR labels**, not from commit
messages. `breaking` bumps major; `feature` / `enhancement` bump minor; everything else
(`security`, `fix`, `bug`, `performance`, `documentation`, `dependencies`, `chore`,
`ci`, `refactor`) bumps patch, and *patch is also the default for a PR with no label at
all*. An unlabelled feature PR therefore silently yields a patch version.

An autolabeler maps conventional-commit PR titles (`feat:`, `fix:`, ...) to labels, but
do not rely on it alone - label every PR explicitly at creation:

```bash
gh pr create ... --label feature
```

### Security fixes

Label anything with a security impact `security`. It groups the change under a
**Security** heading placed above every other section, including Breaking Changes,
because the first question a reader has is whether they must upgrade now.

The label is additive, not exclusive: Release Drafter lists a PR under *every* category
whose labels it carries, so a PR labelled `security` and `fix` appears in both sections.
The autolabeler adds `fix` on its own from a `fix(...)` title, so this is the normal case
rather than the exception - if the repetition reads badly in a particular release, drop
the extra label from the PR before publishing and the draft is rebuilt without it.

A `security` PR is worth a paragraph in the hand-written notes at the top of the release,
saying what was exposed, who is affected and what they should do about it. The generated
bullet says what changed; it does not tell an operator whether to rotate a credential.

## 1. Bump the version

The version lives in **five** files: the root `pyproject.toml`, both package
`pyproject.toml`s, and both package `__init__.py`s. They are kept in sync by
`bump-my-version` (configured under `[tool.bumpversion]` in the root
`pyproject.toml`) - never edit them by hand.

```bash
uv run bump-my-version bump minor    # or patch / major
```

This regenerates `uv.lock` (it records the workspace package versions), commits all six
files, and tags the commit `v{version}`. Before pushing, confirm the bump commit
includes `uv.lock` and the tree is clean:

```bash
git show --stat HEAD    # uv.lock must be listed
git status              # must be clean
```

Then push and wait for CI to pass on the pushed commit:

```bash
git push origin main && git push origin v{version}
```

## 2. Check whether the release introduces a migration

Nothing applies migrations automatically - `fastsmtp serve` does not run Alembic, and
neither does the image. Publishing a release moves the `latest`, `vX` and `vX.Y` tags,
so anything tracking a floating tag can receive a schema-requiring image the moment you
publish. Before publishing, check whether the range since the last release adds a
migration:

```bash
git diff --name-only <last-release-tag>..HEAD -- fastsmtp/src/fastsmtp/alembic/versions/
```

If it does, the release notes **must** say so and state the required order:

1. `fastsmtp db upgrade head` first (it needs only `FASTSMTP_DATABASE_URL`),
2. then move the image.

Since the [startup schema check](configuration.md#schema-version-check) landed, an
image started against a database behind its migrations refuses to start instead of
failing with `UndefinedColumn` on the first query, but that is a runtime backstop, not
a substitute for calling out the migration at release time.

## 3. Publish the release

Release Drafter maintains a **draft** GitHub release on every push to `main`, with the
version resolved from the PR labels above. Review the draft (add the migration note
from step 2 if needed) and publish it:

```bash
gh release edit v{version} --draft=false --latest
```

Publishing triggers `.github/workflows/release.yml`, which checks that CI passed for
the tagged commit (running the test suite itself if it has not), then in parallel:

- builds multi-arch (amd64/arm64) images tagged `vX.Y.Z`, `vX.Y`, `vX`, and `latest`,
- builds and uploads `fastsmtp` and `fastsmtp-cli` to PyPI.

The two upload jobs authenticate with **PyPI Trusted Publishing** over GitHub's OIDC
token, so there is no API token stored anywhere. Each names its own GitHub environment
(`pypi` and `pypi-cli`) because PyPI mints a token per environment and each project's
trusted publisher records the one it expects; a mismatch is rejected. They cannot share
a reusable workflow either - PyPI does not accept one as a trusted publisher.

A **PyPI upload cannot be undone**. A version can be yanked, but the same version
number can never be uploaded again, so a mistake costs a version number. The two
environments are where to put a required reviewer if you want a manual gate in front of
that.

Only a published release uploads. `workflow_dispatch` rebuilds images for a tag that
already shipped, and re-uploading a version PyPI already holds would fail, so the
publish jobs are skipped on that path.

## 4. Verify the images on ghcr

**ghcr is the only source of truth for what is deployable.** The `Release` workflow can
also be run manually via `workflow_dispatch` against an existing tag, useful for
rebuilding an image without cutting a new version, for example after a base-image CVE.
A manually dispatched build pushes images but leaves **no GitHub release** behind, so a
tag can have an image with no release, or neither. Comparing `gh release list` against
`git tag` proves nothing about images; query the registry itself:

```bash
gh api user/packages/container/fastsmtp/versions \
  --jq '.[] | "\(.name[0:19])  \(.metadata.container.tags | join(", "))"'
```

Confirm the new version appears with all four expected tags.

## 5. Verify the packages on PyPI

```bash
pip index versions fastsmtp
pip index versions fastsmtp-cli
```

Both should list the new version. A pip-installed server is not exempt from the
migration discipline in step 2: `fastsmtp db upgrade head` before restarting onto newer
code, exactly as for the image.
