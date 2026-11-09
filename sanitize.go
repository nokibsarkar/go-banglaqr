package banglaqr

import (
	"errors"
	"unicode/utf8"
)

// ErrInvalidText reports invalid UTF-8 or disallowed control characters.
var ErrInvalidText = errors.New("banglaqr: payload contains invalid UTF-8 or control characters")

// Sanitize normalizes scanner/clipboard noise without altering payload
// semantics: it trims surrounding whitespace and drops CR/LF/TAB and zero-width
// characters (ZWSP, ZWNJ, ZWJ, word joiner, BOM). Any other control character
// or invalid UTF-8 is rejected. Bidirectional override/isolate characters and
// line separators are rejected too: they can make a merchant name display
// differently from its bytes. Because the QR CRC is verified afterwards, a
// wrongly removed character cannot yield a valid payload. Clean ASCII input is
// returned without allocation.
func Sanitize(s string) (string, error) {
	// Fast path: printable ASCII, no leading/trailing space.
	clean := len(s) > 0 && s[0] != ' ' && s[len(s)-1] != ' '
	if clean {
		for i := 0; i < len(s); i++ {
			if c := s[i]; c < 0x20 || c >= 0x7F {
				clean = false
				break
			}
		}
	}
	if clean {
		return s, nil
	}
	if !utf8.ValidString(s) {
		return "", ErrInvalidText
	}
	out := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r == '\r' || r == '\n' || r == '\t',
			r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF:
			continue
		case r < 0x20 || r == 0x7F || (r >= 0x80 && r < 0xA0),
			r == 0x2028 || r == 0x2029, // line/paragraph separators
			r == 0x200E || r == 0x200F, // implicit directional marks
			r >= 0x202A && r <= 0x202E, // bidi embeddings/overrides (spoofing)
			r >= 0x2066 && r <= 0x2069: // bidi isolates
			return "", ErrInvalidText
		}
		out = utf8.AppendRune(out, r)
	}
	t := trimSpace(string(out))
	if t == "" {
		return "", ErrInvalidText
	}
	return t, nil
}

func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && s[i] == ' ' {
		i++
	}
	for j > i && s[j-1] == ' ' {
		j--
	}
	return s[i:j]
}
