# Public release preparation

The public source layout is:

| Directory | Contents |
|---|---|
| `final/` | The two standalone Rust crates used by the current paper |
| `vendor/flock-core/` | Pinned GF(2^128) arithmetic and Ligerito dependency, with upstream licenses |
| `scripts/`, `docs/` | Current setup, packaging, validation, and reproduction tools |
| `results/paper/` | Complete timing samples for the three final experiments, aggregate tables, plots, and provenance |
| `archive/` | Descriptions and selected small summaries of earlier Ligerito investigations |

Pre-Ligerito BN254/WHIR implementations and results have been removed. Historical
proof checkpoints, duplicate raw logs, transferred archives, source snapshots,
and temporary executables have also been removed. The public final timing
records are preserved losslessly as gzip files; their measurements have not
been changed. Final proofs can be regenerated and verified by running the suite.

## Validate the publication files

```sh
python3 results/paper/verify.py
python3 scripts/audit_anonymity.py
```

The publication audit scans present files and compressed text for personal local
paths, connection metadata, and credential patterns. It excludes local build
products, `output/`, `.git/`, and `archive/local-artifacts/`. Any original text
changed during sanitation is retained privately under the last directory.
An audit pass covers the checked categories; it does not inspect Git history.
For future result exports with local metadata, inspect the sanitizer's dry-run
report with `python3 scripts/sanitize_public_metadata.py`, then apply it with
`--write` and rerun the audit. Any final result metadata changes require refreshing
its file-checksum inventory; measured raw-record digests must stay unchanged.

Original experiment source/binary hashes describe the executed experiments,
before this repository cleanup. Relocation, extraction of shared helpers,
and metadata sanitation change the current source tree and public file checksums.
Historical transfer/checksum records are execution provenance, rather than
checksums of the reorganized checkout. The release manifest below inventories
the files actually being published. Upstream copyright and license attribution
are retained; see [NOTICE](NOTICE.md).

## Generate the clean public checkout

This local repository's Git history contains large original result blobs and
private historical metadata. A working-tree cleanup does not remove those
objects from old commits. Generate a fresh public directory rather than pushing
this history unchanged:

```sh
python3 scripts/package_release.py output/public-repo
```

The command audits the files, rejects files at or above 100 MiB, copies only the
public source/results/documentation trees, and writes `RELEASE-MANIFEST.json`
with a SHA-256 inventory. It copies no `.git`, build directories, local private
backups, or generated benchmark outputs. The resulting checkout is ready for a
new repository history; create and push that history when ready to publish.
The cleanup does not change remotes, rewrite local commits, or publish anything.

To verify the source package on another machine, compare each file with its
`RELEASE-MANIFEST.json` SHA-256, then follow [docs/reproduce.md](docs/reproduce.md).
The initial dependency installation needs network access; locked builds and
all source dependencies are specified in the package.
