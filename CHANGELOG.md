# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) once tagged.

## [Unreleased]

### Changed
- Module path is `github.com/nokibsarkar/go-banglaqr` (package name stays `banglaqr`).

### Changed
- `GenerateRequest.Amount` is a decimal string and `Template.Amount` returns a
  string: the package is now standard-library only. `Generate` is about 2x faster
  with 45% fewer bytes and 5 instead of 13 allocations.

### Added
- API snapshot test, golden compatibility vectors, zero/nil-value safety test,
  stdlib-only import test, `FuzzGenerate`, and 100% statement coverage.
- Sanitizer, strict parser (CRC-16/CCITT-FALSE, BDT/BD profile checks), compact
  binary codec (`MarshalBinary`/`AppendBinary`/`Decode`), dynamic QR generation.

### Security
- Reject bidirectional override/isolate characters and line separators.
