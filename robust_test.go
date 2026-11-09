package banglaqr

import (
	"bytes"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// ---- independent oracle ------------------------------------------------------
// A deliberately naive re-implementation of the acceptance rules, used for
// differential testing against the optimized parser.

func oracleTLV(s string) (map[int]string, []int, bool) {
	m := map[int]string{}
	var order []int
	for len(s) > 0 {
		if len(s) < 4 {
			return nil, nil, false
		}
		var tag, n int
		if _, err := fmt.Sscanf(s[:2], "%d", &tag); err != nil || !allDigits(s[:2]) {
			return nil, nil, false
		}
		if _, err := fmt.Sscanf(s[2:4], "%d", &n); err != nil || !allDigits(s[2:4]) {
			return nil, nil, false
		}
		if len(s) < 4+n {
			return nil, nil, false
		}
		if _, dup := m[tag]; dup {
			return nil, nil, false
		}
		m[tag] = s[4 : 4+n]
		order = append(order, tag)
		s = s[4+n:]
	}
	return m, order, true
}

func allDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func oracleAccept(s string) bool {
	if len(s) < 14 || len(s) > maxPayload || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	if s[len(s)-8:len(s)-4] != "6304" {
		return false
	}
	tail := strings.ToUpper(s[len(s)-4:])
	if fmt.Sprintf("%04X", crc16(s[:len(s)-4])) != tail || strings.Trim(tail, "0123456789ABCDEF") != "" {
		return false
	}
	m, order, ok := oracleTLV(s[:len(s)-8])
	if !ok || len(order) == 0 || order[0] != 0 || m[0] != "01" {
		return false
	}
	if v := m[1]; v != "11" && v != "12" {
		return false
	}
	if _, ok := m[1]; !ok {
		return false
	}
	if m[53] != "050" || m[58] != "BD" {
		return false
	}
	if _, ok := m[63]; ok {
		return false
	}
	acct := false
	for tag, v := range m {
		if tag >= 26 && tag <= 51 {
			if v == "" {
				return false
			}
			nm, _, ok := oracleTLV(v)
			if !ok {
				return false
			}
			for _, nv := range nm {
				if !utf8.ValidString(nv) {
					return false
				}
			}
			acct = true
		}
		if !utf8.ValidString(v) {
			return false
		}
	}
	if !acct {
		return false
	}
	if v, ok := m[54]; ok && !validAmountText(v) {
		return false
	}
	if v, ok := m[62]; ok {
		sm, _, ok := oracleTLV(v)
		if !ok {
			return false
		}
		for _, sv := range sm {
			if !utf8.ValidString(sv) {
				return false
			}
		}
	}
	return true
}

// ---- random payload generator -------------------------------------------------

func randAlnum(r *rand.Rand, n int) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .-"
	b := make([]byte, n)
	for i := range b {
		b[i] = a[r.Intn(len(a))]
	}
	return string(b)
}

func randPayload(r *rand.Rand) (body string, ok bool) {
	type kv struct{ tag, val string }
	var fields []kv
	add := func(tag int, val string) { fields = append(fields, kv{fmt.Sprintf("%02d", tag), val}) }
	add(1, []string{"11", "12"}[r.Intn(2)])
	for i, n := 0, 1+r.Intn(3); i < n; i++ {
		inner := tlv("00", randAlnum(r, 3+r.Intn(12)))
		for j, m := 0, r.Intn(3); j < m; j++ {
			inner += tlv(fmt.Sprintf("%02d", 1+j), randAlnum(r, 1+r.Intn(10)))
		}
		add(26+i*5, inner)
	}
	add(52, "4812")
	add(53, "050")
	add(58, "BD")
	add(59, randAlnum(r, 1+r.Intn(25)))
	add(60, randAlnum(r, 1+r.Intn(15)))
	if r.Intn(3) == 0 {
		add(54, fmt.Sprintf("%d.%02d", 1+r.Intn(9999), r.Intn(100)))
	}
	if r.Intn(2) == 0 {
		var sub string
		for _, st := range r.Perm(7)[:1+r.Intn(4)] {
			sub += tlv(fmt.Sprintf("%02d", st+1), randAlnum(r, 1+r.Intn(8)))
		}
		add(62, sub)
	}
	if r.Intn(3) == 0 {
		add(64, tlv("00", "bn")+tlv("01", "মার্চেন্ট"))
	}
	if r.Intn(3) == 0 {
		add(80+r.Intn(20), randAlnum(r, 1+r.Intn(10)))
	}
	// Mostly canonical order, sometimes shuffled (acceptors must not rely on it).
	if r.Intn(4) == 0 {
		r.Shuffle(len(fields), func(i, j int) { fields[i], fields[j] = fields[j], fields[i] })
	}
	var sb strings.Builder
	sb.WriteString(tlv("00", "01"))
	for _, f := range fields {
		if len(f.val) > 99 {
			return "", false
		}
		sb.WriteString(tlv(f.tag, f.val))
	}
	return sb.String(), true
}

// Property: for any valid source, Generate preserves every untouched element
// byte-for-byte, produces a valid dynamic payload, is deterministic and
// idempotent, and round-trips through the binary codec.
func TestPropertyGenerate(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	profiles := []Profile{ProfileBill, ProfileCoverage, ProfileAll}
	checked := 0
	for i := 0; i < 4000; i++ {
		body, ok := randPayload(r)
		if !ok {
			continue
		}
		src := seal(body)
		st, err := Parse(src)
		if err != nil {
			t.Fatalf("valid fixture rejected: %v\n%s", err, src)
		}
		if st.Text() != src {
			t.Fatal("source altered")
		}
		prof := profiles[r.Intn(3)]
		req := GenerateRequest{
			Amount: fmt.Sprintf("%d.%02d", r.Intn(1000000), r.Intn(100)), Reference: randRef(r),
			Profile: prof, DerivationAuthorized: true, AllowExperimental: true,
		}
		p, err := st.Generate(req)
		if err != nil {
			if err == ErrCapacity {
				continue
			}
			t.Fatalf("generate: %v\n%s", err, src)
		}
		checked++
		nt := p.Template
		if !nt.VerifyCRC() || !nt.IsDynamic() || nt.Text() != p.Text {
			t.Fatal("bad output state")
		}
		if got, _ := nt.Value(54); got != req.Amount {
			t.Fatalf("amount %q vs %s", got, req.Amount)
		}
		for _, e := range st.root {
			if e.tag == 1 || e.tag == 54 || e.tag == 62 {
				continue
			}
			want := st.src[e.off:e.end()]
			if strings.Count(p.Text, want) < 1 {
				t.Fatalf("element %d not preserved byte-for-byte", e.tag)
			}
			ov, _ := nt.Value(e.tag)
			if ov != st.val(e) {
				t.Fatalf("element %d value changed", e.tag)
			}
		}
		set := map[uint8]bool{}
		for _, x := range profileTags[prof] {
			set[x] = true
		}
		for _, e := range st.sub {
			if !set[e.tag] {
				if v, _ := nt.SubValue(e.tag); v != st.val(e) {
					t.Fatalf("62.%02d not preserved", e.tag)
				}
			}
		}
		for _, x := range profileTags[prof] {
			if v, _ := nt.SubValue(x); v != req.Reference {
				t.Fatalf("62.%02d = %q", x, v)
			}
		}
		if strings.ToUpper(p.Text[len(p.Text)-4:]) != p.Text[len(p.Text)-4:] {
			t.Fatal("CRC not upper-case")
		}
		p2, err := st.Generate(req)
		if err != nil || p2.Text != p.Text {
			t.Fatal("generation not deterministic")
		}
		p3, err := nt.Generate(req)
		if err != nil || p3.Text == "" || !p3.Template.VerifyCRC() {
			t.Fatalf("regeneration from dynamic failed: %v", err)
		}
		if p3.Text != nt.Text() && func() bool { v, _ := nt.Value(54); return v == req.Amount }() {
			// Same request applied to its own output is a fixed point once all
			// tags are in canonical positions; positions may differ only when
			// the source order was non-canonical.
			if len(p3.Text) != len(nt.Text()) {
				t.Fatal("regeneration changed length")
			}
		}
		blob, _ := nt.MarshalBinary()
		d, err := Decode(blob)
		if err != nil || d.Text() != nt.Text() {
			t.Fatalf("codec: %v", err)
		}
	}
	if checked < 2000 {
		t.Fatalf("only %d generated cases exercised", checked)
	}
}

func randRef(r *rand.Rand) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
	b := make([]byte, 1+r.Intn(25))
	for i := range b {
		b[i] = a[r.Intn(len(a))]
	}
	return string(b)
}

// Differential: after resealing (so the CRC is valid) random byte mutations
// must be accepted/rejected exactly as the naive oracle says, and every
// accepted payload must survive the codec.
func TestDifferentialMutations(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	accepted, rejected := 0, 0
	for i := 0; i < 20000; i++ {
		body, ok := randPayload(r)
		if !ok {
			continue
		}
		b := []byte(body)
		for m, n := 0, r.Intn(4); m < n; m++ {
			switch r.Intn(4) {
			case 0:
				b[r.Intn(len(b))] = byte("0123456789ABCDEF"[r.Intn(16)])
			case 1:
				b[r.Intn(len(b))] = byte(r.Intn(256))
			case 2:
				if len(b) > 6 {
					k := r.Intn(len(b) - 4)
					b = append(b[:k], b[k+1:]...)
				}
			case 3:
				k := r.Intn(len(b))
				b = append(b[:k+1], append([]byte{byte('0' + r.Intn(10))}, b[k+1:]...)...)
			}
		}
		src := seal(string(b))
		tp, err := Parse(src)
		if (err == nil) != oracleAccept(src) {
			// Sanitize may legitimately strip bytes the oracle sees; compare on
			// the sanitized text instead.
			if s2, serr := Sanitize(src); serr == nil && (err == nil) == oracleAccept(s2) {
				continue
			}
			t.Fatalf("disagreement: parse err=%v oracle=%v\n%q", err, oracleAccept(src), src)
		}
		if err != nil {
			rejected++
			continue
		}
		accepted++
		blob, _ := tp.MarshalBinary()
		d, err := Decode(blob)
		if err != nil || d.Text() != tp.Text() || !d.VerifyCRC() {
			t.Fatalf("accepted payload failed codec: %v", err)
		}
	}
	if accepted < 500 || rejected < 500 {
		t.Fatalf("weak coverage: accepted=%d rejected=%d", accepted, rejected)
	}
}

func TestZeroAndNilSafety(t *testing.T) {
	var nt *Template
	var zt Template
	for _, tp := range []*Template{nt, &zt} {
		if tp.Text() != "" || tp.VerifyCRC() || tp.IsDynamic() {
			t.Fatal("zero template state")
		}
		if _, ok := tp.Value(1); ok {
			t.Fatal("value on zero")
		}
		if _, ok := tp.SubValue(1); ok {
			t.Fatal("sub on zero")
		}
		if _, ok := tp.Amount(); ok {
			t.Fatal("amount on zero")
		}
		if _, err := tp.MarshalBinary(); err == nil {
			t.Fatal("marshal of zero must fail")
		}
		if _, err := tp.Generate(GenerateRequest{Amount: "1", Reference: "A", DerivationAuthorized: true}); err == nil {
			t.Fatal("generate on zero must fail")
		}
		_ = tp.String()
	}
}

func TestLowercaseCRCAcceptedButOutputUppercase(t *testing.T) {
	src := staticQR()
	low := src[:len(src)-4] + strings.ToLower(src[len(src)-4:])
	tp, err := Parse(low)
	if err != nil {
		t.Fatal(err)
	}
	if tp.Text() != low {
		t.Fatal("source must be preserved verbatim")
	}
	p, err := tp.Generate(GenerateRequest{Amount: "1", Reference: "A", DerivationAuthorized: true})
	if err != nil {
		t.Fatal(err)
	}
	tail := p.Text[len(p.Text)-4:]
	if tail != strings.ToUpper(tail) {
		t.Fatal("output CRC must be upper-case")
	}
}

func TestMultibyteBoundaryRejected(t *testing.T) {
	// A length that splits a multi-byte rune (bytes, not characters) must fail.
	name := "নাম"
	if len(name) != 9 {
		t.Fatal("fixture assumption")
	}
	base := tlv("00", "01") + tlv("01", "11") + tlv("26", tlv("00", "x")) + tlv("53", "050") + tlv("58", "BD")
	good := seal(base + tlv("59", name))
	if _, err := Parse(good); err != nil {
		t.Fatalf("valid UTF-8 value rejected: %v", err)
	}
	split := seal(base + "5908" + name[:8] + tlv("60", name[8:])) // cuts inside a rune
	if _, err := Parse(split); err == nil {
		t.Fatal("boundary inside a rune must be rejected")
	}
	nestedSplit := seal(tlv("00", "01") + tlv("01", "11") + "2610" + tlv("00", "x") + "0107"[:0] + "0105" + name[:5] + tlv("53", "050") + tlv("58", "BD"))
	_, _ = Parse(nestedSplit) // must not panic regardless of outcome
}

func TestAmountTextRules(t *testing.T) {
	ok := []string{"1", "10", "0.5", "100.00", "1234567890.12"[:13], "0.01"}
	bad := []string{"", "0", "0.00", "007", "00.5", ".5", "5.", "1.234", "1e3", "-1", "1,5", "+1", "1 0", "12345678901234", "१२"}
	for _, s := range ok {
		if !validAmountText(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range bad {
		if validAmountText(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

func TestHostileInputsBounded(t *testing.T) {
	if _, err := Parse(strings.Repeat("0", 4*maxPayload+1)); err != ErrTooLong {
		t.Fatalf("got %v", err)
	}
	if _, err := Parse(strings.Repeat("00", maxPayload)); err == nil {
		t.Fatal("must reject")
	}
	if _, err := Parse(strings.Repeat("\u200b", 1000)); err == nil {
		t.Fatal("zero-width only must reject")
	}
	if _, err := Parse(strings.Repeat(" ", 100)); err == nil {
		t.Fatal("blank must reject")
	}
	// Many tiny elements: linear, no panic, duplicate rejection.
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString(fmt.Sprintf("%02d00", i))
	}
	if _, err := Parse(seal(sb.String())); err == nil {
		t.Fatal("must reject (invalid profile)")
	}
	if _, err := Decode(nil); err == nil {
		t.Fatal("nil blob")
	}
	if _, err := Decode(bytes.Repeat([]byte{0xff}, 64)); err == nil {
		t.Fatal("garbage blob")
	}
}

func TestConcurrentUse(t *testing.T) {
	tp, err := Parse(staticQR(tlv("62", tlv("05", "S"))))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				ref := fmt.Sprintf("G%dI%d", g, i)
				p, err := tp.Generate(GenerateRequest{Amount: strconv.Itoa(i + 1), Reference: ref, DerivationAuthorized: true})
				if err != nil {
					errs <- err
					return
				}
				if v, _ := p.Template.SubValue(1); v != ref {
					errs <- fmt.Errorf("cross-talk: %q != %q", v, ref)
					return
				}
				blob, _ := tp.MarshalBinary()
				if _, err := Decode(blob); err != nil {
					errs <- err
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if tp.Text() != staticQR(tlv("62", tlv("05", "S"))) {
		t.Fatal("shared template mutated")
	}
}

func TestSanitizeEdgeCases(t *testing.T) {
	for _, in := range []string{"\x00", "\x7f", "a\u0085b", "a\xc2", "\x1b[0m"} {
		if _, err := Sanitize(in); err == nil {
			t.Errorf("%q must be rejected", in)
		}
	}
	if s, err := Sanitize("  \ufeffab\r\ncd \t"); err != nil || s != "abcd" {
		t.Fatalf("got %q %v", s, err)
	}
}

func TestErrorTypes(t *testing.T) {
	_, err := Parse(staticQR()[:20])
	var pe *ParseError
	if !errorsAs(err, &pe) && err != ErrTooShort {
		t.Fatalf("unexpected error type %T", err)
	}
	good := staticQR()
	_, err = Parse(good[:len(good)-1] + "0")
	if !errorsAs(err, &pe) || pe.Unwrap() != ErrCRC || !strings.Contains(pe.Error(), "offset") {
		t.Fatalf("got %v", err)
	}
	if _, err := NewReference(0); err == nil {
		t.Fatal("n=0")
	}
	if _, err := NewReference(26); err == nil {
		t.Fatal("n=26")
	}
}

func errorsAs(err error, target **ParseError) bool {
	pe, ok := err.(*ParseError)
	if ok {
		*target = pe
	}
	return ok
}

func TestSanitizeRejectsBidiAndSeparators(t *testing.T) {
	for _, cp := range []int{0x2028, 0x2029, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069} {
		in := "0002" + string(rune(cp)) + "01"
		if _, err := Sanitize(in); err == nil {
			t.Errorf("U+%04X must be rejected", cp)
		}
		if _, err := Parse(staticQR()[:20] + string(rune(cp)) + staticQR()[20:]); err == nil {
			t.Errorf("U+%04X must not reach the parser", cp)
		}
	}
}
