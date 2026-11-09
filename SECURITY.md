# Security policy

Report vulnerabilities privately through GitHub's "Report a vulnerability"
(Security tab) on this repository; do not open a public issue.

In scope: a payload that parses but should be rejected (or the reverse), output
that differs from the template in anything but tags 01, 54, 62 and the CRC,
input that makes the package panic, hang, or allocate without bound, and any way
to make an invalid stored blob decode. Never include real merchant data; use
synthetic QR strings.

Only the latest minor release is supported.
