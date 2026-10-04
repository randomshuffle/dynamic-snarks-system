# Licenses and upstream attribution

Project Rust packages are available under MIT OR Apache-2.0, as declared in their
Cargo manifests. The license texts are [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).

The vendored [flock-core](vendor/flock-core/) provides GF(2^128) arithmetic and
the Ligerito PCS. Its [upstream record](vendor/flock-core/UPSTREAM.md) identifies
revision `879072249e52b8b9054bf0c6a034cec20f8f6fc7` of
https://github.com/succinctlabs/flock and describes the local compatibility and
parameter changes. Original upstream licenses and copyright notices are retained
in that directory.

Other Rust dependencies are pinned in the individual crate lockfiles and retain
their own licenses.

Result directories contain measurements, experiment descriptions, and generated
plots. Historical provenance records identify the sources used for those runs;
they are distinct from the reorganized public-source inventory.
