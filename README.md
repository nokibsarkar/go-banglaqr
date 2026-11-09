# go-banglaqr

[![ci](https://github.com/nokibsarkar/go-banglaqr/actions/workflows/ci.yml/badge.svg)](https://github.com/nokibsarkar/go-banglaqr/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/nokibsarkar/go-banglaqr.svg)](https://pkg.go.dev/github.com/nokibsarkar/go-banglaqr)

A small, fast, dependency-free Go package for EMVCo merchant-presented
**Bangla QR**: sanitize scanner text, parse and validate, store compactly, and
derive amount-specific (dynamic) QR payloads from an authorized static merchant
QR.

```bash
go get github.com/nokibsarkar/go-banglaqr
```

```go
import banglaqr "github.com/nokibsarkar/go-banglaqr"
```

It is local and deterministic: no network, no image renderer (hand `Payload.Text`
to any QR encoder) and no third-party modules. A generated payload is a payment
instruction, **never evidence that a payment happened**: confirm payments with
your acquirer.

## Features


- `Parse` – sanitizes scanner noise, verifies CRC-16/CCITT-FALSE, enforces BDT/BD/tag-01/merchant-account invariants, rejects duplicates and truncation. One pass, flat offset index.
- `Template.MarshalBinary` / `Decode` – compact blob for DB storage; decoding skips value scanning and the QR CRC, validating a CRC-32C trailer and that the index tiles the payload exactly. `VerifyCRC()` is available for untrusted storage.
- `Generate` – copies every untouched element byte-for-byte; sets 01=12, 54, 62.01 (bill profile; coverage/all are explicit experimental opt-ins), re-appends CRC, re-parses the result. Requires `DerivationAuthorized`: you confirm your acquiring contract permits deriving dynamic QR codes from the static one.

## Usage

```go
tpl, err := banglaqr.Parse(scannedText)            // sanitize + validate
blob, _ := tpl.MarshalBinary()                     // store this (~payload + 4 B/element)

tpl, err = banglaqr.Decode(blob)                   // fast path for stored templates
p, err := tpl.Generate(banglaqr.GenerateRequest{
    Amount:               "100.50",                // decimal string, BDT, max 2 decimals
    Reference:            "INV-1001",
    DerivationAuthorized: true,                    // you confirm the acquirer allows this
})
// p.Text is the dynamic QR payload for a frontend QR encoder.
```

Errors are matched with `errors.Is` against the exported `Err*` values or
`errors.As` to `*ParseError` (byte offset).

## Stability

Semantic versioning; additions only within a major version. The exported API is
pinned by a snapshot test (`testdata/api.txt`), stored-blob and generated-payload
compatibility vectors are pinned in `golden_test.go`, the binary format carries
a version byte, and `GenerateRequest` requires keyed literals so fields can be
added later. See the package documentation.

## Footprint

Standard library only (no third-party modules). Indicative numbers on a laptop
CPU: `Parse` ≈ 0.5 µs / 160 B / 3 allocs, `Decode` ≈ 0.3 µs / 244 B / 4 allocs,
`Generate` ≈ 1 µs / 368 B / 5 allocs.

## Quality gates

100% statement coverage (enforced in CI), `-race`, shuffled tests, fuzzers for
parse, decode and generate, oracle/property tests, `staticcheck`, `govulncheck`.

```bash
go test -race -cover ./...
go test -run xxx -bench . -benchmem
go test -run xxx -fuzz FuzzParse -fuzztime 30s   # also FuzzDecode, FuzzGenerate
```

## Related projects

- [go-payment](https://github.com/nokibsarkar/go-payment) – a vendor-neutral Go
  payment SDK whose Bangla QR adapter is built on this package. This package does
  not depend on it.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[GNU Affero General Public License v3.0 or later](LICENSE).
