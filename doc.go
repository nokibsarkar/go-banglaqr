// Package banglaqr parses, sanitizes and transforms EMVCo merchant-presented
// Bangla QR payloads, and generates amount-specific (dynamic) QR text from an
// authorized static merchant template (SRS §11, QR-01..QR-18).
//
// It is standalone: local, deterministic, no network, no renderer and no
// dependency on a payment SDK. A generated payload is a payment instruction,
// never evidence of payment.
//
// A parsed Template is an immutable, compact, stateful value: the original
// payload bytes plus a flat offset index. It serializes to a small binary blob
// (MarshalBinary / AppendBinary) suitable for database storage; UnmarshalBinary
// rebuilds it without rescanning values or recomputing the QR CRC, validating
// only the index structure and a CRC-32C integrity trailer.
//
// Lengths are counted in bytes. Non-ASCII UTF-8 is preserved byte-for-byte;
// invalid UTF-8 and control characters are rejected (fail closed).
//
// # Stability
//
// The exported API is pinned by testdata/api.txt and compatibility vectors in
// golden_test.go, and follows semantic versioning from v1.0.0:
//
//   - Only additions happen within a major version: new functions, methods,
//     struct fields, error values and Profile constants.
//   - Construct GenerateRequest with keyed fields (the type enforces this), so
//     new fields never break callers.
//   - Match errors with errors.Is / errors.As against the exported Err* values
//     and *ParseError. Error message text is not part of the API.
//   - The binary template format is versioned (byte 2). Blobs written by any
//     released version keep decoding; a future format gets a new version number
//     and Decode keeps reading the old ones. An unknown version fails with
//     ErrBlobVersion rather than being guessed at.
//   - Generated payload text for a given template and request is stable.
//   - Amounts are plain decimal strings, so the API depends on nothing outside
//     the standard library.
//
// # Footprint
//
// The package imports only the standard library and keeps no global state
// beyond two constant lookup tables. Parse makes three allocations and a
// Template costs the payload plus 4 bytes per element; Decode and Generate
// avoid rescanning and intermediate copies (see the benchmarks).
package banglaqr
