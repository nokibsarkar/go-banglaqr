package banglaqr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"strings"
	"testing"
)

// index lists the TLV elements of a flat TLV string starting at offset base.
func index(s string, base int) []elem {
	var es []elem
	for pos := 0; pos < len(s); {
		tag := uint8((s[pos]-'0')*10 + s[pos+1] - '0')
		n := uint8((s[pos+2]-'0')*10 + s[pos+3] - '0')
		es = append(es, elem{tag: tag, n: n, off: uint16(base + pos)})
		pos += 4 + int(n)
	}
	return es
}

// rawBlob assembles a correctly checksummed blob from arbitrary parts, so the
// structural checks behind the checksum can be exercised.
func rawBlob(flags byte, srcLen uint64, src string, lists ...[]byte) []byte {
	b := []byte{'B', 'Q', 1, flags}
	b = binary.AppendUvarint(b, srcLen)
	b = append(b, src...)
	for _, l := range lists {
		b = append(b, l...)
	}
	return binary.LittleEndian.AppendUint32(b, crc32.Checksum(b, castagnoli))
}

func encList(es ...elem) []byte {
	b := binary.AppendUvarint(nil, uint64(len(es)))
	for _, e := range es {
		b = append(b, e.tag)
		b = binary.AppendUvarint(b, uint64(e.off))
		b = append(b, e.n)
	}
	return b
}

func TestDecodeStructuralRejections(t *testing.T) {
	body := tlv("00", "01") + tlv("01", "11") + tlv("26", tlv("00", "example.test")) +
		tlv("53", "050") + tlv("58", "BD")
	src := seal(body)
	root := index(body, 0)
	empty := encList()
	ok := func(flags byte) []byte { return rawBlob(flags, uint64(len(src)), src, encList(root...), empty) }

	if _, err := Decode(ok(0)); err != nil {
		t.Fatalf("baseline blob must decode: %v", err)
	}

	withSrc := func(s string, r []elem, sub []elem, flags byte) []byte {
		return rawBlob(flags, uint64(len(s)), s, encList(r...), encList(sub...))
	}
	mut := func(f func(es []elem)) []elem {
		es := append([]elem(nil), root...)
		f(es)
		return es
	}
	badTail := src[:len(src)-8] + "6305" + src[len(src)-4:]
	badHex := src[:len(src)-4] + "ZZZZ"
	invalidUTF8 := seal(tlv("00", "01") + tlv("01", "11") + tlv("26", tlv("00", "x")) +
		tlv("53", "050") + tlv("58", "BD") + tlv("59", "\xc3"))
	emptyAcct := seal(tlv("00", "01") + tlv("01", "11") + tlv("26", "") + tlv("53", "050") + tlv("58", "BD"))
	emptyAcctBody := emptyAcct[:len(emptyAcct)-8]
	invBody := invalidUTF8[:len(invalidUTF8)-8]
	noAcct := seal(tlv("00", "01") + tlv("01", "11") + tlv("53", "050") + tlv("58", "BD"))
	noAcctBody := noAcct[:len(noAcct)-8]
	with62 := seal(body + tlv("62", tlv("05", "S")))
	with62Body := with62[:len(with62)-8]

	cases := []struct {
		name string
		blob []byte
	}{
		{"short source length", rawBlob(0, 13, src[:13], empty, empty)},
		{"source length beyond blob", rawBlob(0, uint64(len(src))+50, src, empty, empty)},
		{"source length beyond maxPayload", rawBlob(0, maxPayload+1, src, empty, empty)},
		{"source length varint missing", []byte{'B', 'Q', 1, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0, 0, 0}},
		{"too many root elements", rawBlob(0, uint64(len(src)), src, binary.AppendUvarint(nil, 101), empty)},
		{"count varint missing", rawBlob(0, uint64(len(src)), src, []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80})},
		{"elements missing", rawBlob(0, uint64(len(src)), src, binary.AppendUvarint(nil, 1))},
		{"offset varint missing", rawBlob(0, uint64(len(src)), src, []byte{1, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80})},
		{"offset beyond maxPayload", rawBlob(0, uint64(len(src)), src, []byte{1, 0, 0xFF, 0xFF, 0x7F, 2}, empty)},
		{"length byte missing", rawBlob(0, uint64(len(src)), src, []byte{1, 0, 0})},
		{"tag over 99", rawBlob(0, uint64(len(src)), src, []byte{1, 100, 0, 2}, empty)},
		{"length over 99", rawBlob(0, uint64(len(src)), src, []byte{1, 0, 0, 100}, empty)},
		{"trailing bytes", rawBlob(0, uint64(len(src)), src, encList(root...), empty, []byte{9})},
		{"crc tail marker wrong", withSrc(badTail, root, nil, 0)},
		{"crc tail not hex", withSrc(badHex, root, nil, 0)},
		{"root offset gap", withSrc(src, mut(func(es []elem) { es[1].off++ }), nil, 0)},
		{"root element past end", withSrc(src, mut(func(es []elem) { es[len(es)-1].n = 90 }), nil, 0)},
		{"root duplicate tag", withSrc(src, mut(func(es []elem) { es[1].tag = 0 }), nil, 0)},
		{"root header mismatch", withSrc(src, mut(func(es []elem) { es[1].n++ }), nil, 0)},
		{"root header tag mismatch", withSrc(src, mut(func(es []elem) { es[1].tag = 2 }), nil, 0)},
		{"root does not cover source", withSrc(src, root[:len(root)-1], nil, 0)},
		{"sub list without tag 62", withSrc(src, root, []elem{{tag: 5, n: 1, off: 8}}, 0)},
		{"sub list gap", withSrc(with62, index(with62Body, 0), []elem{{tag: 5, n: 1, off: 9999 % 4000}}, 4)},
		{"profile invariant fails", withSrc(noAcct, index(noAcctBody, 0), nil, 0)},
		{"invalid UTF-8 value", withSrc(invalidUTF8, index(invBody, 0), nil, 0)},
		{"empty account value", withSrc(emptyAcct, index(emptyAcctBody, 0), nil, 0)},
		{"flags disagree", ok(2)},
	}
	for _, c := range cases {
		if _, err := Decode(c.blob); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}

	// The sub-list tiling check runs against the real tag-62 range.
	subOK := index(tlv("05", "S"), len(body)+4)
	if tp, err := Decode(withSrc(with62, index(with62Body, 0), subOK, 4)); err != nil || tp == nil {
		t.Fatalf("valid sub list must decode: %v", err)
	}
	subBad := append([]elem(nil), subOK...)
	subBad[0].off++
	if _, err := Decode(withSrc(with62, index(with62Body, 0), subBad, 4)); !errors.Is(err, ErrBlob) {
		t.Fatalf("sub tiling error expected, got %v", err)
	}
}

func TestParseHex4Edges(t *testing.T) {
	for _, s := range []string{"", "ABC", "ABCDE"} {
		if _, ok := parseHex4(s); ok {
			t.Errorf("%q accepted", s)
		}
	}
	for s, want := range map[string]uint16{"0000": 0, "ffff": 0xFFFF, "AbCd": 0xABCD} {
		if v, ok := parseHex4(s); !ok || v != want {
			t.Errorf("%q = %x %v", s, v, ok)
		}
	}
	if _, ok := parseHex4("12G4"); ok {
		t.Error("non-hex accepted")
	}
}

func TestGenerateTopLevelErrors(t *testing.T) {
	req := GenerateRequest{Amount: "1", Reference: "R1", DerivationAuthorized: true}
	if _, err := Generate("not a qr", req); err == nil {
		t.Fatal("malformed template accepted")
	}
	var nilT *Template
	if _, err := nilT.Generate(req); !errors.Is(err, ErrMissingTag) {
		t.Fatalf("nil template: %v", err)
	}
	if _, err := nilT.MarshalBinary(); !errors.Is(err, ErrBlob) {
		t.Fatal("nil marshal")
	}
}

func TestGenerateCapacityAndAmountBounds(t *testing.T) {
	long := staticQR(tlv("62", tlv("50", "0123456789012345678901234567890123456789012345678901234567890123456789")))
	p, err := Parse(long)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Generate(GenerateRequest{Amount: "1", Reference: "ABCDEFGHIJKLMNOPQRSTUVWXY", DerivationAuthorized: true}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity: %v", err)
	}
	big, _ := Parse(staticQR())
	if _, err := big.Generate(GenerateRequest{Amount: "99999999999.99", Reference: "R1", DerivationAuthorized: true}); !errors.Is(err, ErrAmount) {
		t.Fatalf("amount length: %v", err)
	}
	if _, err := NewReference(0); !errors.Is(err, ErrBadReference) {
		t.Fatal("zero length reference")
	}
	if _, err := NewReference(26); !errors.Is(err, ErrBadReference) {
		t.Fatal("over-long reference")
	}
	r, err := NewReference(25)
	if err != nil || len(r) != 25 {
		t.Fatal("reference")
	}
}

func TestGenerateRevalidatesOversizedOutput(t *testing.T) {
	// A template that is legal on its own but whose dynamic form would exceed
	// the payload limit must be rejected by the output re-parse.
	tagStr := func(n int) string { return fmt.Sprintf("%02d", n) }
	body := tlv("00", "01") + tlv("01", "11") + tlv("53", "050") + tlv("58", "BD")
	for tag := 26; tag <= 51; tag++ {
		body += tlv(tagStr(tag), tlv("00", strings.Repeat("a", 95)))
	}
	for tag := 65; len(body)+12 < maxPayload-110; tag++ {
		body += tlv(tagStr(tag), strings.Repeat("a", 95))
	}
	pad := maxPayload - 8 - len(body) - 4 - 5 // fill to just under the limit
	body += tlv("99", strings.Repeat("a", pad))
	tp, err := Parse(seal(body))
	if err != nil {
		t.Fatalf("base template must parse: %v (len %d)", err, len(body)+8)
	}
	_, err = tp.Generate(GenerateRequest{Amount: "1", Reference: "ABCDEFGHIJ", DerivationAuthorized: true})
	if !errors.Is(err, ErrTooLong) {
		t.Fatalf("expected ErrTooLong from output revalidation, got %v", err)
	}
}

func FuzzGenerate(f *testing.F) {
	f.Add(staticQR(), "1.00", "REF1", uint8(0))
	f.Add(staticQR(tlv("62", tlv("05", "S"))), "99999.99", "A", uint8(1))
	f.Fuzz(func(t *testing.T, tmpl, amount, ref string, prof uint8) {
		tp, err := Parse(tmpl)
		if err != nil {
			return
		}
		p, err := tp.Generate(GenerateRequest{
			Amount: amount, Reference: ref, Profile: Profile(prof % 4),
			AllowExperimental: true, DerivationAuthorized: true,
		})
		if err != nil {
			return
		}
		out, err := Parse(p.Text)
		if err != nil || !out.VerifyCRC() || !out.IsDynamic() {
			t.Fatalf("generated payload invalid: %v", err)
		}
		got, ok := out.Amount()
		if !ok {
			t.Fatal("amount missing")
		}
		// Oracle: exact rational equality between input and emitted amount.
		in, ok1 := new(big.Rat).SetString(amount)
		em, ok2 := new(big.Rat).SetString(got)
		if !ok1 || !ok2 || in.Cmp(em) != 0 || in.Sign() <= 0 {
			t.Fatalf("amount %q emitted as %q", amount, got)
		}
		if _, err := tp.MarshalBinary(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAmountGrammar(t *testing.T) {
	good := map[string]string{
		"1": "1.00", "100": "100.00", "100.5": "100.50", "100.50": "100.50",
		"0.05": "0.05", "0.5": "0.50", "9999999999.99": "9999999999.99",
	}
	for in, want := range good {
		got, ok := appendAmount(nil, in)
		if !ok || string(got) != want {
			t.Errorf("%q -> %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{
		"", ".", ".5", "1.", "1.234", "-1", "+1", " 1", "1 ", "1e2", "0x1", "1,000",
		"0", "0.0", "0.00", "00.1", "01", "12345678901", "1..2", "1.2.3", "\u0661",
	} {
		if got, ok := appendAmount(nil, in); ok {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}
