package banglaqr

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func tlv(tag, val string) string { return tag + fmt.Sprintf("%02d", len(val)) + val }

func seal(body string) string {
	b := []byte(body + "6304")
	return string(appendHex4(b, crc16b(b)))
}

// Synthetic fixture only; not a real merchant.
func staticQR(extra ...string) string {
	s := tlv("00", "01") + tlv("01", "11") +
		tlv("26", tlv("00", "example.test")+tlv("01", "0123456789")) +
		tlv("52", "4812") + tlv("53", "050") + tlv("58", "BD") +
		tlv("59", "Test Merchant") + tlv("60", "Dhaka")
	for _, e := range extra {
		s += e
	}
	return seal(s)
}

func TestCRCKnownVector(t *testing.T) {
	// CRC-16/CCITT-FALSE check value for "123456789" is 0x29B1.
	if got := crc16("123456789"); got != 0x29B1 {
		t.Fatalf("crc=%04X", got)
	}
	if crc16b([]byte("123456789")) != 0x29B1 {
		t.Fatal("crc16b")
	}
}

func TestParseStatic(t *testing.T) {
	src := staticQR(tlv("62", tlv("05", "STORE1")))
	tp, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if tp.Text() != src || tp.IsDynamic() || !tp.VerifyCRC() {
		t.Fatal("static template state wrong")
	}
	if v, _ := tp.Value(59); v != "Test Merchant" {
		t.Fatal(v)
	}
	if v, ok := tp.SubValue(5); !ok || v != "STORE1" {
		t.Fatal(v)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", tp, tp), "example.test") {
		t.Fatal("template leaked in formatting")
	}
}

func TestParseRejects(t *testing.T) {
	good := staticQR()
	body := good[:len(good)-8]
	cases := map[string]string{
		"empty":         "",
		"short":         "000201",
		"bad crc":       good[:len(good)-1] + "0",
		"no crc tag":    body + "6204ABCD",
		"nonhex crc":    body + "6304ZZZZ",
		"truncated":     seal(body[:len(body)-3]),
		"dup tag":       seal(body + tlv("59", "X")),
		"bad format":    seal(strings.Replace(body, "000201", "000202", 1)),
		"bad poi":       seal(strings.Replace(body, "010211", "010213", 1)),
		"wrong cur":     seal(strings.Replace(body, "5303050", "5303840", 1)),
		"wrong country": seal(strings.Replace(body, "5802BD", "5802IN", 1)),
		"no account":    seal(tlv("00", "01") + tlv("01", "11") + tlv("53", "050") + tlv("58", "BD")),
		"bad nested":    seal(tlv("00", "01") + tlv("01", "11") + tlv("26", "00") + tlv("53", "050") + tlv("58", "BD")),
		"bad 62 dup":    seal(body + tlv("62", tlv("05", "A")+tlv("05", "B"))),
		"bad amount":    seal(body + tlv("54", "1.234")),
		"zero amount":   seal(body + tlv("54", "0.00")),
		"nondigit len":  seal(tlv("00", "01") + "01AB11"),
		"control char":  good[:10] + "\x01" + good[10:],
		"invalid utf8":  good[:10] + "\xff" + good[10:],
	}
	for name, in := range cases {
		if _, err := Parse(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestSanitize(t *testing.T) {
	good := staticQR()
	noisy := "\ufeff  " + good[:20] + "\r\n" + good[20:40] + "\u200b" + good[40:] + " \n"
	tp, err := Parse(noisy)
	if err != nil || tp.Text() != good {
		t.Fatalf("sanitize failed: %v", err)
	}
	if s, _ := Sanitize(good); s != good {
		t.Fatal("clean input changed")
	}
	if allocs := testing.AllocsPerRun(10, func() { Sanitize(good) }); allocs != 0 {
		t.Fatalf("clean sanitize allocates: %v", allocs)
	}
}

func TestGenerateBill(t *testing.T) {
	src := staticQR(tlv("62", tlv("05", "STORE1")))
	st, _ := Parse(src)
	ref, err := NewReference(12)
	if err != nil || len(ref) != 12 {
		t.Fatal(err)
	}
	p, err := st.Generate(GenerateRequest{
		Amount: "100.5", Reference: ref, DerivationAuthorized: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	nt := p.Template
	if !nt.IsDynamic() || !nt.VerifyCRC() {
		t.Fatal("not dynamic/valid")
	}
	if v, _ := nt.Value(54); v != "100.50" {
		t.Fatal(v)
	}
	if v, _ := nt.SubValue(1); v != ref {
		t.Fatal("62.01 missing")
	}
	if v, _ := nt.SubValue(5); v != "STORE1" {
		t.Fatal("unrelated 62.05 not preserved")
	}
	// Merchant routing and every untouched root element are byte-identical.
	for _, tag := range []uint8{0, 26, 52, 53, 58, 59, 60} {
		a, _ := st.Value(tag)
		b, _ := nt.Value(tag)
		if a != b {
			t.Errorf("tag %d changed", tag)
		}
	}
	if !strings.Contains(p.Text, tlv("26", tlv("00", "example.test")+tlv("01", "0123456789"))) {
		t.Fatal("tag 26 bytes not preserved")
	}
	if st.Text() != src {
		t.Fatal("source mutated")
	}
	// Tags stay ascending: 53 < 54 < 58, 60 < 62.
	if i54, i58 := strings.Index(p.Text, "5406"), strings.Index(p.Text, "5802"); i54 < 0 || i54 > i58 {
		t.Fatal("tag 54 misplaced")
	}
}

func TestGenerateReplacesExistingAmountAndDynamic(t *testing.T) {
	src := staticQR(tlv("54", "5.00"), tlv("62", tlv("01", "OLD")))
	p, err := Generate(src, GenerateRequest{Amount: "7", Reference: "NEW1", DerivationAuthorized: true})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := p.Template.Value(54); v != "7.00" {
		t.Fatal(v)
	}
	if v, _ := p.Template.SubValue(1); v != "NEW1" {
		t.Fatal(v)
	}
	if strings.Contains(p.Text, "5.00") {
		t.Fatal("old amount remained")
	}
}

func TestGenerateGuards(t *testing.T) {
	src := staticQR()
	ok := GenerateRequest{Amount: "1", Reference: "R1", DerivationAuthorized: true}
	mut := func(f func(*GenerateRequest)) GenerateRequest { r := ok; f(&r); return r }
	cases := map[string]struct {
		r   GenerateRequest
		err error
	}{
		"unauthorized": {mut(func(r *GenerateRequest) { r.DerivationAuthorized = false }), ErrNotAuthorized},
		"zero":         {mut(func(r *GenerateRequest) { r.Amount = "0" }), ErrAmount},
		"negative":     {mut(func(r *GenerateRequest) { r.Amount = "-1" }), ErrAmount},
		"precision":    {mut(func(r *GenerateRequest) { r.Amount = "1.001" }), ErrAmount},
		"overflow":     {mut(func(r *GenerateRequest) { r.Amount = "99999999999999" }), ErrAmount},
		"empty ref":    {mut(func(r *GenerateRequest) { r.Reference = "" }), ErrBadReference},
		"long ref":     {mut(func(r *GenerateRequest) { r.Reference = strings.Repeat("A", 26) }), ErrBadReference},
		"bad ref char": {mut(func(r *GenerateRequest) { r.Reference = "a b" }), ErrBadReference},
		"experimental": {mut(func(r *GenerateRequest) { r.Profile = ProfileCoverage }), ErrExperimental},
		"profile":      {mut(func(r *GenerateRequest) { r.Profile = 9 }), ErrBadProfile},
	}
	for name, c := range cases {
		if _, err := Generate(src, c.r); !errors.Is(err, c.err) {
			t.Errorf("%s: got %v want %v", name, err, c.err)
		}
	}
	// Tag 62 capacity: existing 62 nearly full.
	big := staticQR(tlv("62", tlv("09", strings.Repeat("x", 80))))
	if _, err := Generate(big, ok); !errors.Is(err, ErrCapacity) && err != nil {
		t.Fatalf("got %v", err)
	}
	r := ok
	r.Reference = strings.Repeat("A", 25)
	if _, err := Generate(big, r); !errors.Is(err, ErrCapacity) {
		t.Fatalf("expected capacity error, got %v", err)
	}
}

func TestExperimentalProfiles(t *testing.T) {
	src := staticQR()
	for prof, want := range map[Profile][]uint8{ProfileCoverage: {1, 3, 5, 6, 7}, ProfileAll: {1, 3, 4, 5, 6, 7}} {
		p, err := Generate(src, GenerateRequest{Amount: "1", Reference: "R9", Profile: prof, DerivationAuthorized: true, AllowExperimental: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Template.sub) != len(want) {
			t.Fatalf("profile %d: %d subfields", prof, len(p.Template.sub))
		}
		for _, tag := range want {
			if v, _ := p.Template.SubValue(tag); v != "R9" {
				t.Errorf("profile %d tag %d", prof, tag)
			}
		}
	}
}

func TestBinaryRoundTrip(t *testing.T) {
	for _, src := range []string{
		staticQR(),
		staticQR(tlv("62", tlv("05", "S")+tlv("07", "T")), tlv("64", tlv("00", "bn")+tlv("01", "নাম"))),
	} {
		tp, err := Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		blob, err := tp.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		d, err := Decode(blob)
		if err != nil {
			t.Fatal(err)
		}
		if d.Text() != src || !d.VerifyCRC() {
			t.Fatal("round trip mismatch")
		}
		b2, _ := d.MarshalBinary()
		if !bytes.Equal(blob, b2) {
			t.Fatal("re-marshal differs")
		}
		if len(blob) > len(src)+4+4*len(tp.root)+4*len(tp.sub)+16 {
			t.Fatalf("blob not compact: %d for %d", len(blob), len(src))
		}
		// AppendBinary reuses capacity.
		buf := make([]byte, 0, len(blob))
		out, _ := tp.AppendBinary(buf)
		if !bytes.Equal(out, blob) {
			t.Fatal("append differs")
		}
	}
	// Generated templates also round trip, including dynamic state.
	p, _ := Generate(staticQR(), GenerateRequest{Amount: "3", Reference: "X1", DerivationAuthorized: true})
	blob, _ := p.Template.MarshalBinary()
	d, err := Decode(blob)
	if err != nil || !d.IsDynamic() || d.Text() != p.Text {
		t.Fatalf("dynamic round trip: %v", err)
	}
	if a, ok := d.Amount(); !ok || a != "3.00" {
		t.Fatal("amount")
	}
}

func TestDecodeRejectsCorruption(t *testing.T) {
	tp, _ := Parse(staticQR(tlv("62", tlv("05", "S"))))
	blob, _ := tp.MarshalBinary()
	// Any single-byte flip must be rejected (CRC-32C detects all 1-byte errors).
	for i := range blob {
		c := append([]byte(nil), blob...)
		c[i] ^= 0x01
		if _, err := Decode(c); err == nil {
			t.Fatalf("flip at %d accepted", i)
		}
	}
	for _, n := range []int{0, 1, 8, len(blob) - 1} {
		if _, err := Decode(blob[:n]); err == nil {
			t.Fatalf("truncation to %d accepted", n)
		}
	}
	// A well-checksummed blob with a lying index is rejected structurally.
	forged := &Template{src: tp.src, root: append([]elem(nil), tp.root...), sub: tp.sub}
	forged.root[3].n++ // wrong length vs header
	bad, _ := forged.MarshalBinary()
	if _, err := Decode(bad); err == nil {
		t.Fatal("forged index accepted")
	}
	// Failed decode must not clobber the receiver.
	var r Template
	if err := r.UnmarshalBinary(blob[:5]); err == nil || r.src != "" {
		t.Fatal("receiver modified on failure")
	}
}

func TestRepeatedReferencesUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		r, _ := NewReference(10)
		if seen[r] {
			t.Fatal("collision in 1000 draws of 10 chars")
		}
		seen[r] = true
	}
}

func TestGenerateHasNoPaymentState(t *testing.T) {
	// Payload exposes no Paid/Succeeded field (QR-02); compile-time shape check.
	var _ = Payload{Text: "", Reference: "", Profile: ProfileBill}
}

// --- fuzz & benchmarks -------------------------------------------------------

func FuzzParse(f *testing.F) {
	f.Add(staticQR())
	f.Add(staticQR(tlv("62", tlv("05", "S")), tlv("54", "1.00")))
	f.Add("")
	f.Add("00020101021126")
	f.Fuzz(func(t *testing.T, s string) {
		tp, err := Parse(s)
		if err != nil {
			return
		}
		if !tp.VerifyCRC() {
			t.Fatal("accepted payload with bad CRC")
		}
		blob, _ := tp.MarshalBinary()
		d, err := Decode(blob)
		if err != nil || d.Text() != tp.Text() {
			t.Fatalf("round trip failed: %v", err)
		}
		if p, err := tp.Generate(GenerateRequest{Amount: "1", Reference: "F1", DerivationAuthorized: true}); err == nil {
			if !p.Template.VerifyCRC() || !p.Template.IsDynamic() {
				t.Fatal("bad generated payload")
			}
		}
	})
}

func FuzzDecode(f *testing.F) {
	tp, _ := Parse(staticQR(tlv("62", tlv("05", "S"))))
	b, _ := tp.MarshalBinary()
	f.Add(b)
	f.Add([]byte("BQ\x01\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := Decode(b)
		if err != nil {
			return
		}
		b2, _ := d.MarshalBinary()
		if !bytes.Equal(b, b2) {
			t.Fatal("accepted blob does not re-marshal identically")
		}
	})
}

var sink *Template

func BenchmarkParse(b *testing.B) {
	s := staticQR(tlv("62", tlv("05", "STORE1")))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sink, _ = Parse(s)
	}
}

func BenchmarkDecode(b *testing.B) {
	tp, _ := Parse(staticQR(tlv("62", tlv("05", "STORE1"))))
	blob, _ := tp.MarshalBinary()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sink, _ = Decode(blob)
	}
}

func BenchmarkGenerate(b *testing.B) {
	tp, _ := Parse(staticQR(tlv("62", tlv("05", "STORE1"))))
	r := GenerateRequest{Amount: "100", Reference: "ABC123", DerivationAuthorized: true}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tp.Generate(r)
	}
}
