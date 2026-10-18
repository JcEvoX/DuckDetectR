# Release policy

Stable releases are built by `.github/workflows/release-latest.yml` from an existing `v*` tag.
Manual releases must start the workflow from the repository's default branch and name an existing
tag; the workflow never creates a tag from a branch head.

## Trusted source history

A stable release tag must point to a commit reachable from the repository's default branch. This
keeps tag-controlled Gradle and Android build logic inside the same reviewed history that is
allowed to receive the release signing credentials.

## Historical rebuild compatibility

Historical rebuilds are supported starting at commit
`641913a4efa743b200454b10b4d2e41ac02f1f39` (inclusive). That revision introduced the complete
`duckdetector.android.*` toolchain property contract consumed by the current shared Android setup
action. Tags on older commits are rejected rather than built with guessed modern SDK, build-tools,
CMake, or NDK versions.

The release workflow uses the workflow revision's shared setup action through the `$/` self-
repository reference while building source from the selected tag. The selected source tree still
supplies its own pinned toolchain values and Gradle build logic.

## Release immutability

Enable the repository's **Release immutability** setting. All newly published releases,
including stable releases and Nightly archives, must report `immutable: true`. Both workflows
verify this state after publication. Stable publication does not overwrite existing assets.

The existing, already published `nightly` prerelease is the only mutable exception. GitHub's
setting applies to future publications, so this pre-existing release remains mutable. Never
unpublish, delete, recreate or republish it; recreating it under the enabled policy would lock
its update assets and tag. Channel updates modify assets and notes without a draft transition.
The Nightly workflow stops if this channel is missing, unpublished or immutable, rather than
attempting to recreate it. The stable workflow rejects the reserved literal `nightly` tag.

GitHub locks release assets and the associated tag; release titles, notes and latest/prerelease
metadata can still be edited. The repository currently has no older releases to migrate other
than the mutable `nightly` exception.

References: [GitHub immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
and [enabling the policy](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes).

## Nightly archives and the update channel

Each default-branch Nightly is archived under `nightly-yyyy-MM-dd-gitshortHash`, using the
build-start UTC date and the first eight hexadecimal characters of the full commit SHA.
The tag must resolve to that full commit. The APK, SDK AAR and schema-v1 `update.json` are
uploaded to a draft, verified, and only then published as a prerelease. Published archives
must be immutable and are never replaced; a rerun on the same date/commit reuses the existing complete archive.
Only unpublished draft attempts may be discarded and rebuilt. GitHub may assign draft assets
a temporary `untagged-*` URL; manifests always contain the final archive URL. The draft URL,
asset identity, size and digest are checked before publication, and permanent URLs afterwards.

The fixed `nightly` tag remains the compatibility and discovery channel:

- Checks still read `releases/download/nightly/update.json`; no release-list API is needed.
- The manifest's original `apk` object points to an APK under `nightly`, as existing clients
  require. Its schema version and legacy `master` branch value remain unchanged.
- An optional `archive` object identifies the immutable tag and the same APK bytes there.
  New clients require the names, sizes and hashes to agree, select the immutable URL, and
  independently verify against that tag's official manifest. Legacy clients ignore the addition.
- The channel is advanced only after its public archive and both compatibility assets have
  been verified. The manifest is replaced last. If this upload/verification fails, the previous
  manifest is restored when one exists. GitHub asset replacement is not a transaction; a brief
  missing-manifest response is possible and remains subject to the client's existing HTTP retries.
- Only the literal `nightly` ref may move. Its ref is updated after the pointer is verified.
  An older version/build time cannot move the channel backwards; interrupted ref updates can
  be repaired by rerunning the workflow without replacing the archive or the current pointer.
- Compatibility APK/AAR filenames include the immutable tag. Existing channel assets are
  reused only after byte verification, never clobbered or automatically deleted, so older
  downloads retain their URLs. The channel therefore also retains compatibility copies of
  historical binaries; archive retention and channel retention must be considered separately.

The Telegram step uses the verified archived APK bytes. It sends a notification only when
this run advances the update channel; a rerun of an already current channel does not resend it.
The publishing helpers' offline fixtures run in CI as `test-nightly-release.py` and
`test-nightly-channel.py`, including the workflow's actual manifest-building script.

API semantics: [GitHub releases](https://docs.github.com/en/rest/releases/releases) and
[release assets](https://docs.github.com/en/rest/releases/assets). The already pinned
[release action](https://github.com/softprops/action-gh-release) uploads the draft assets.
