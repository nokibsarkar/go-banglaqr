package banglaqr

import (
	"errors"
	"strconv"
)

// Sentinel errors; parse failures wrap them in *ParseError.
var (
	ErrTooShort     = errors.New("banglaqr: payload too short")
	ErrTooLong      = errors.New("banglaqr: payload too long")
	ErrCRCFormat    = errors.New("banglaqr: missing or malformed CRC field")
	ErrCRC          = errors.New("banglaqr: CRC mismatch")
	ErrMalformedTLV = errors.New("banglaqr: malformed TLV header")
	ErrTruncated    = errors.New("banglaqr: truncated TLV element")
	ErrDuplicateTag = errors.New("banglaqr: duplicate tag")
	ErrMissingTag   = errors.New("banglaqr: required tag missing or invalid")
	ErrUnsupported  = errors.New("banglaqr: unsupported or non-Bangla-QR profile")
	ErrAmount       = errors.New("banglaqr: invalid amount")
)

// ParseError carries the byte offset of the failure.
type ParseError struct {
	Offset int
	Err    error
}

func (e *ParseError) Error() string {
	return e.Err.Error() + " (offset " + strconv.Itoa(e.Offset) + ")"
}
func (e *ParseError) Unwrap() error { return e.Err }

const maxPayload = 4096 // offsets fit uint16 with wide margin

// elem indexes one TLV element: off is the offset of its 4-byte header in the
// source, n the value length. 4 bytes of tag/len + off => 4 bytes per entry.
type elem struct {
	tag uint8
	n   uint8
	off uint16
}

func (e elem) end() int { return int(e.off) + 4 + int(e.n) }

// scan splits s into TLV elements in one pass, rejecting malformed headers,
// truncation and duplicate tags. base is s's offset within the full payload.
func scan(s string, base int, out []elem) ([]elem, error) {
	var seen [100]bool
	for i := 0; i < len(s); {
		if len(s)-i < 4 {
			return out, &ParseError{base + i, ErrTruncated}
		}
		a, b, c, d := s[i]-'0', s[i+1]-'0', s[i+2]-'0', s[i+3]-'0'
		if a > 9 || b > 9 || c > 9 || d > 9 {
			return out, &ParseError{base + i, ErrMalformedTLV}
		}
		tag, n := a*10+b, c*10+d
		if len(s)-i-4 < int(n) {
			return out, &ParseError{base + i, ErrTruncated}
		}
		if seen[tag] {
			return out, &ParseError{base + i, ErrDuplicateTag}
		}
		seen[tag] = true
		out = append(out, elem{tag: tag, n: n, off: uint16(base + i)})
		i += 4 + int(n)
	}
	return out, nil
}

// Parse sanitizes and parses a payload, verifying its CRC and the Bangla QR
// profile invariants. Unsupported templates fail closed.
func Parse(s string) (*Template, error) {
	// Bound work on hostile input before any allocation: noise stripping can
	// only shrink the text, and a valid payload is at most maxPayload bytes.
	if len(s) > 4*maxPayload {
		return nil, ErrTooLong
	}
	s, err := Sanitize(s)
	if err != nil {
		return nil, err
	}
	return parseClean(s)
}

func parseClean(s string) (*Template, error) {
	n := len(s)
	if n < 14 {
		return nil, ErrTooShort
	}
	if n > maxPayload {
		return nil, ErrTooLong
	}
	if s[n-8:n-4] != "6304" {
		return nil, &ParseError{n - 8, ErrCRCFormat}
	}
	want, ok := parseHex4(s[n-4:])
	if !ok {
		return nil, &ParseError{n - 4, ErrCRCFormat}
	}
	if crc16(s[:n-4]) != want {
		return nil, &ParseError{n - 4, ErrCRC}
	}
	root, err := scan(s[:n-8], 0, make([]elem, 0, 16))
	if err != nil {
		return nil, err
	}
	t := &Template{src: s, root: root}
	if st, en, ok := t.range62(); ok {
		if t.sub, err = scan(s[st:en], st, make([]elem, 0, 8)); err != nil {
			return nil, err
		}
	}
	if err := t.finish(true); err != nil {
		return nil, err
	}
	return t, nil
}

// validAmountText: digits with optional ".d" or ".dd", at most 13 chars, > 0.
func validAmountText(s string) bool {
	if len(s) == 0 || len(s) > 13 {
		return false
	}
	if s[0] == '0' && len(s) > 1 && s[1] != '.' {
		return false // no ambiguous leading zeros ("007.00")
	}
	dot := -1
	nonZero := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if dot >= 0 || i == 0 || i == len(s)-1 {
				return false
			}
			dot = i
		case c-'0' <= 9:
			if c != '0' {
				nonZero = true
			}
		default:
			return false
		}
	}
	if dot >= 0 && len(s)-dot-1 > 2 {
		return false
	}
	return nonZero
}
