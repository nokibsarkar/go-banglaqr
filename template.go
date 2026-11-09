package banglaqr

import (
	"unicode/utf8"
)

// Template is an immutable parsed payload: source text plus a flat offset
// index of root elements and of tag-62 sub-elements. Safe for concurrent use.
type Template struct {
	src  string
	root []elem
	sub  []elem // tag 62 sub-elements, offsets absolute into src
}

// String is redacted: merchant routing fields stay out of default logs.
func (t *Template) String() string { return "banglaqr.Template{redacted}" }

// GoString is redacted too.
func (t *Template) GoString() string { return t.String() }

// Text returns the exact source payload (including CRC), unchanged.
func (t *Template) Text() string {
	if t == nil {
		return ""
	}
	return t.src
}

func (t *Template) val(e elem) string { return t.src[int(e.off)+4 : e.end()] }

// Value returns the root-level value of a tag (0..99).
func (t *Template) Value(tag uint8) (string, bool) {
	if t == nil {
		return "", false
	}
	for _, e := range t.root {
		if e.tag == tag {
			return t.val(e), true
		}
	}
	return "", false
}

// SubValue returns a tag-62 additional-data sub-field value.
func (t *Template) SubValue(tag uint8) (string, bool) {
	if t == nil {
		return "", false
	}
	for _, e := range t.sub {
		if e.tag == tag {
			return t.val(e), true
		}
	}
	return "", false
}

// IsDynamic reports point-of-initiation "12". This is a semantic flag only; it
// implies no single-use or expiry guarantee.
func (t *Template) IsDynamic() bool { v, _ := t.Value(1); return v == "12" }

// Amount returns the text of tag 54 (for example "100.50") if present. It is
// the exact string from the payload, already validated by Parse.
func (t *Template) Amount() (string, bool) {
	if t == nil {
		return "", false
	}
	return t.Value(54)
}

// VerifyCRC recomputes the QR CRC over the stored text. Parse already did;
// call this after UnmarshalBinary when the storage layer is not trusted.
func (t *Template) VerifyCRC() bool {
	if t == nil || len(t.src) < 14 {
		return false
	}
	n := len(t.src)
	want, ok := parseHex4(t.src[n-4:])
	return ok && crc16(t.src[:n-4]) == want
}

func (t *Template) range62() (start, end int, ok bool) {
	for _, e := range t.root {
		if e.tag == 62 {
			return int(e.off) + 4, e.end(), true
		}
	}
	return 0, 0, false
}

func (t *Template) flags() byte {
	var f byte
	if t.IsDynamic() {
		f |= 1
	}
	if _, ok := t.Value(54); ok {
		f |= 2
	}
	if _, _, ok := t.range62(); ok {
		f |= 4
	}
	return f
}

// finish checks Bangla QR profile invariants on an indexed template.
func (t *Template) finish(nested bool) error {
	// Element boundaries are byte-based; a boundary inside a multi-byte rune
	// would yield a value that is not valid UTF-8 on its own. Fail closed.
	// Every nested element is delimited by ASCII headers (or the end of its
	// parent value), so valid root values imply valid nested values and only
	// the root needs checking.
	if !isASCII(t.src) {
		for _, e := range t.root {
			if !utf8.ValidString(t.val(e)) {
				return &ParseError{int(e.off), ErrInvalidText}
			}
		}
	}
	if len(t.root) == 0 || t.root[0].tag != 0 || t.val(t.root[0]) != "01" {
		return &ParseError{0, ErrMissingTag}
	}
	var have53, have58, haveAcct bool
	for _, e := range t.root {
		v := t.val(e)
		switch {
		case e.tag == 1:
			if v != "11" && v != "12" {
				return &ParseError{int(e.off), ErrMissingTag}
			}
		case e.tag == 53:
			if v != "050" {
				return &ParseError{int(e.off), ErrUnsupported}
			}
			have53 = true
		case e.tag == 58:
			if v != "BD" {
				return &ParseError{int(e.off), ErrUnsupported}
			}
			have58 = true
		case e.tag == 54:
			if !validAmountText(v) {
				return &ParseError{int(e.off), ErrAmount}
			}
		case e.tag == 63:
			return &ParseError{int(e.off), ErrDuplicateTag}
		case e.tag >= 26 && e.tag <= 51:
			if len(v) == 0 {
				return &ParseError{int(e.off), ErrUnsupported}
			}
			if nested {
				var buf [16]elem
				base := int(e.off) + 4
				if _, err := scan(v, base, buf[:0]); err != nil {
					return err
				}
			}
			haveAcct = true
		}
	}
	if _, ok := t.Value(1); !ok || !have53 || !have58 || !haveAcct {
		return &ParseError{0, ErrMissingTag}
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
