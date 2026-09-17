# Anonymous artifact preparation

The checked-in files have been prepared for anonymous review. Personal paths,
the original repository URL, instance addresses, and identifying Git revision
metadata were replaced with neutral placeholders. Source and result tar archives
were sanitized recursively, including their owner names, numeric owner IDs,
extended headers, and archive timestamps. Referenced SHA-256 checksums and
source-manifest digests were refreshed for the sanitized files.

These are publication copies of the recorded artifacts. An archive's current
digest describes the sanitized copy. The Rust implementation, benchmark
measurements in CSV files, and serialized proof checkpoints are unchanged.
Hardware specifications, software versions, experiment parameters, and measured
times remain available for reproducing and interpreting the results. Upstream
dependency attribution and license declarations are retained.

Paths under `/path/to/` or `/home/anonymous/`, the `example.invalid` repository
URL, `benchmark.example.invalid`, and `192.0.2.1` are placeholders. Substitute
your checkout, anonymous clone URL, or benchmark host before running a command
that uses one of them.

Before publishing another version, run:

```sh
python3 scripts/audit_anonymity.py
```

The check includes tracked files, nonignored new files, nested tar archives,
and archive ownership metadata. In a Git checkout, it derives additional search
terms from local commit identities and the origin's owner. Use repeated
`--forbid-term` arguments to check additional names, emails, usernames, or URLs;
keep those private search terms out of committed scripts and reports. The scan
does not prove anonymity against every possible form of correlation.

Fresh benchmark runs and source/result packaging can capture identifying paths
or archive ownership again. Review and sanitize new artifacts before adding them
to the publication version.

The local `.git` directory, original commit history, remote settings, ignored
build outputs, and private backups are outside this content audit. Publish the
sanitized revision through an anonymizer that hides repository ownership and
history, or use a fresh anonymous snapshot. Do not include `.git` or private
backups in a shared archive. Confirm that the anonymizer serves the sanitized
revision rather than an earlier version.
