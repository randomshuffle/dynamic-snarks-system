# Publication metadata

See [PUBLICATION.md](PUBLICATION.md) for the current public layout, metadata
checks, and clean-checkout generation command. Earlier versions of this document
applied to an older BN254/WHIR artifact; that implementation and its results
have been removed.

The final recorded timing samples are unchanged. Public metadata may replace
personal local paths and connection details; original source hashes remain
records of the executed experiments. Public snapshot checksums are recorded
separately. Upstream licenses and authorship notices remain intact.

`.git/`, generated build directories, and ignored local sanitation backups must
not be included in the public snapshot. The publication audit does not erase
or sanitize Git history; use the fresh checkout produced by `package_release.py`.
