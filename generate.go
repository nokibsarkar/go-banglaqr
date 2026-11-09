package banglaqr

import (
	"crypto/rand"
	"errors"
	"strings"
)

// Profile selects which tag-62 sub-fields receive the reference.
type Profile uint8

const (
	// ProfileBill (default, production): 62.01 only.
	ProfileBill Profile = iota
	// ProfileCoverage (experimental): 62.01, .03, .05, .06, .07.
	ProfileCoverage
	// ProfileAll (experimental): coverage plus .04.
	ProfileAll
)

var profileTags = [...][]uint8{
	ProfileBill:     {1},
	ProfileCoverage: {1, 3, 5, 6, 7},
	ProfileAll:      {1, 3, 4, 5, 6, 7},
}

var (
	ErrNotAuthorized = errors.New("banglaqr: derivation from this template is not confirmed as authorized")
	ErrExperimental  = errors.New("banglaqr: experimental profile requires explicit opt-in")
	ErrBadReference  = errors.New("banglaqr: invalid reference")
	ErrCapacity      = errors.New("banglaqr: reference does not fit tag 62 capacity")
	ErrBadProfile    = errors.New("banglaqr: unknown profile")
)

// GenerateRequest describes one dynamic payload. Currency is always BDT.
type GenerateRequest struct {
	// Amount is a plain decimal string in BDT: digits with an optional "." and
	// at most two fractional digits, no sign, exponent, separators or leading
	// zeros ("100", "100.5", "0.05"). It must be greater than zero and fit the
	// 13-character EMV amount field. It is emitted as "100.50".
	Amount    string
	Reference string // 1..25 of [A-Za-z0-9._-]; see NewReference
	Profile   Profile
	// DerivationAuthorized must be true: the caller confirms that deriving a
	// dynamic QR from this source is permitted by the acquiring contract.
	DerivationAuthorized bool
	// AllowExperimental must be true for any profile other than ProfileBill.
	AllowExperimental bool

	_ struct{} // forces keyed literals so fields can be added compatibly
}

// Payload is the generation result. It carries no payment state.
type Payload struct {
	Text      string // full TLV payload; populate a presentation's QRData with it
	Reference string
	Profile   Profile
	Template  *Template // parsed result, storable via MarshalBinary
}

const maxReference = 25

func validReference(r string) bool {
	if len(r) == 0 || len(r) > maxReference {
		return false
	}
	for i := 0; i < len(r); i++ {
		c := r[i]
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// NewReference returns an n-character (1..25) cryptographically random
// reference over [A-Z2-7]. Durable uniqueness per merchant is application-owned.
func NewReference(n int) (string, error) {
	if n < 1 || n > maxReference {
		return "", ErrBadReference
	}
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails: crypto/rand.Read aborts the process instead
	for i := range b {
		b[i] = alpha[b[i]&31]
	}
	return string(b), nil
}

func put2(b []byte, v int) []byte { return append(b, byte('0'+v/10), byte('0'+v%10)) }

func writeTLV(sb *strings.Builder, tag string, v []byte) {
	sb.WriteString(tag)
	sb.WriteByte(byte('0' + len(v)/10))
	sb.WriteByte(byte('0' + len(v)%10))
	sb.Write(v)
}

func appendRef(b []byte, tag uint8, ref string) []byte {
	b = put2(b, int(tag))
	b = put2(b, len(ref))
	return append(b, ref...)
}

func inProfile(p Profile, tag uint8) bool {
	for _, x := range profileTags[p] {
		if x == tag {
			return true
		}
	}
	return false
}

// appendAmount appends the canonical two-decimal form of a strictly positive
// amount, or reports false. It accepts only digits with an optional "." and at
// most two fractional digits, and no leading zeros (QR amounts are strings, so
// no float or big-number type is involved).
func appendAmount(dst []byte, s string) ([]byte, bool) {
	dot := strings.IndexByte(s, '.')
	ip, fp := s, ""
	if dot >= 0 {
		ip, fp = s[:dot], s[dot+1:]
		if len(fp) == 0 || len(fp) > 2 {
			return dst, false
		}
	}
	if len(ip) == 0 || len(ip) > 10 || (ip[0] == '0' && len(ip) > 1) {
		return dst, false
	}
	nonZero := false
	for _, part := range [2]string{ip, fp} {
		for i := 0; i < len(part); i++ {
			if part[i]-'0' > 9 {
				return dst, false
			}
			if part[i] != '0' {
				nonZero = true
			}
		}
	}
	if !nonZero {
		return dst, false
	}
	dst = append(dst, ip...)
	dst = append(dst, '.')
	dst = append(dst, fp...)
	for n := len(fp); n < 2; n++ {
		dst = append(dst, '0')
	}
	return dst, true
}

// Generate parses a static template and produces a dynamic payload. Every
// unmodified root element is copied byte-for-byte; only tag 01 (set to 12),
// tag 54 (amount), tag 62 (reference, preserving unrelated sub-fields) and the
// CRC change. The result is re-parsed and fully revalidated.
func Generate(template string, req GenerateRequest) (*Payload, error) {
	t, err := Parse(template)
	if err != nil {
		return nil, err
	}
	return t.Generate(req)
}

// Generate is the method form for an already-parsed (e.g. decoded) template.
func (t *Template) Generate(req GenerateRequest) (*Payload, error) {
	if t == nil || len(t.root) == 0 {
		return nil, ErrMissingTag
	}
	if !req.DerivationAuthorized {
		return nil, ErrNotAuthorized
	}
	if int(req.Profile) >= len(profileTags) {
		return nil, ErrBadProfile
	}
	if req.Profile != ProfileBill && !req.AllowExperimental {
		return nil, ErrExperimental
	}
	if !validReference(req.Reference) {
		return nil, ErrBadReference
	}
	var abuf [16]byte
	amt, ok := appendAmount(abuf[:0], req.Amount)
	if !ok {
		return nil, ErrAmount
	}

	// Build the new tag-62 value, preserving unrelated sub-fields. 99 bytes is
	// the TLV maximum, so the common case never leaves the stack.
	var vbuf [100]byte
	v62 := vbuf[:0]
	var written [100]bool
	for _, e := range t.sub {
		if inProfile(req.Profile, e.tag) {
			v62 = appendRef(v62, e.tag, req.Reference)
			written[e.tag] = true
		} else {
			v62 = append(v62, t.src[e.off:e.end()]...)
		}
	}
	for _, tag := range profileTags[req.Profile] {
		if !written[tag] {
			v62 = appendRef(v62, tag, req.Reference)
		}
	}
	if len(v62) > 99 {
		return nil, ErrCapacity
	}

	// One allocation for the output; the CRC is computed over the builder's
	// own bytes and the final string is returned without a copy.
	var sb strings.Builder
	sb.Grow(len(t.src) + len(v62) + len(amt) + 16)
	w54, w62 := false, false
	for _, e := range t.root {
		if !w54 && e.tag >= 54 {
			w54 = true
			writeTLV(&sb, "54", amt)
		}
		if !w62 && e.tag >= 62 {
			w62 = true
			writeTLV(&sb, "62", v62)
		}
		switch e.tag {
		case 54, 62:
			continue // replaced (emitted at first position >= its tag)
		case 1:
			sb.WriteString("010212")
		default:
			sb.WriteString(t.src[e.off:e.end()])
		}
	}
	// Tag 54 has always been written by now: tag 58 is mandatory and sorts after it.
	if !w62 {
		writeTLV(&sb, "62", v62)
	}
	sb.WriteString("6304")
	c := crc16(sb.String())
	sb.WriteByte(hexUpper[c>>12])
	sb.WriteByte(hexUpper[c>>8&15])
	sb.WriteByte(hexUpper[c>>4&15])
	sb.WriteByte(hexUpper[c&15])

	text := sb.String()
	nt, err := parseClean(text) // revalidate the output
	if err != nil {
		return nil, err
	}
	return &Payload{Text: text, Reference: req.Reference, Profile: req.Profile, Template: nt}, nil
}
