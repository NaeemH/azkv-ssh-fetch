# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Ship a PEP 561 `py.typed` marker. The package is fully annotated and CI
  enforces `mypy --strict`, but without the marker type checkers ignored the
  annotations entirely, so none of that typing was usable downstream. (#6)

## [0.1.3] - 2026-06-22

### Added

- Integration tests for `connect`, asserting the `az network bastion ssh`
  argv, that the key is mode 0600 before `az` is invoked, and the
  `--keep-key` / `--shred-key`, nonzero-exit, missing-`az` and `OSError`
  paths. Coverage rose from 78% to 91% overall. (#4)

### Changed

- Source the version dynamically from `__about__.py` so a release only
  requires bumping one file. (#3)

## [0.1.2] - 2026-06-22

### Fixed

- Three latent bugs in the cassette recording infrastructure. These affected
  anyone attempting to record fixtures, not just new recordings. (#2)
- Bump the static `version` field in `pyproject.toml` as well as
  `__about__.py`. The first 0.1.2 build rebuilt 0.1.1 and PyPI rejected it as
  a duplicate.

### Added

- A `pytest-recording` / VCR replay layer, with committed cassettes. (#1)

## [0.1.1] - 2026-06-22

### Changed

- Documentation and CI polish.

## [0.1.0] - 2026-06-18

### Added

- Initial release: fetch SSH private keys from Azure Key Vault and connect to
  VMs and VMSS instances through Azure Bastion.
