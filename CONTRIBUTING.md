# Contributing

The bar is "never a surprise":

- Standard library only. No third-party modules.
- 100% statement coverage, enforced in CI. Unreachable code is deleted, not
  excluded.
- Public API changes are deliberate: `go test -run TestPublicAPIIsPinned
  -update-api` rewrites `testdata/api.txt`; only additions are acceptable within
  a major version. Never change golden vectors.
- Validate strictly and fail closed; every rejection path needs a test.
- Keep allocations flat: check `go test -run xxx -bench . -benchmem` before and
  after.

```bash
go vet ./... && go test -race -shuffle=on -cover ./...
go test -run xxx -fuzz FuzzParse -fuzztime 30s   # also FuzzDecode, FuzzGenerate
```
