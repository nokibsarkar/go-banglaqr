package banglaqr

import (
	"encoding/hex"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Compatibility vectors. Stored templates and generated payloads must keep
// meaning the same thing across releases: if one of these changes, the change is
// breaking. The binary format is versioned (byte 2); new versions may be added
// but blobs of every released version must keep decoding.
const (
	goldenStatic     = "00020101021126300012example.test011001234567895204481253030505802BD5913Test Merchant6005Dhaka62050501S6304A628"
	goldenDynamic    = "00020101021226300012example.test011001234567895204481253030505406100.505802BD5913Test Merchant6005Dhaka62140501S0105INV-163048D64"
	goldenStaticBlob = "425101046e30303032303130313032313132363330303031326578616d706c652e7465737430313130303132333435363738393532303434383132353330333035303538303242443539313354657374204d65726368616e74363030354468616b613632303530353031533633303441363238090000020106021a0c1e342e043536033a3d023b430d3c54053e5d05010561011ef8596f"
	goldenDynBlob    = "42510107810130303032303130313032313232363330303031326578616d706c652e746573743031313030313233343536373839353230343438313235333033303530353430363130302e35303538303242443539313354657374204d65726368616e74363030354468616b6136323134303530315330313035494e562d3136333034384436340a0000020106021a0c1e342e04353603363d063a47023b4d0d3c5e053e670e02056b010170058b78a0ac"
)

func TestGoldenVectors(t *testing.T) {
	if golden := staticQR(tlv("62", tlv("05", "S"))); golden != goldenStatic {
		t.Fatalf("fixture drifted: %s", golden)
	}
	p, err := Generate(goldenStatic, GenerateRequest{Amount: "100.5", Reference: "INV-1", DerivationAuthorized: true})
	if err != nil || p.Text != goldenDynamic {
		t.Fatalf("dynamic payload changed: %v\n%s", err, p.Text)
	}
	for _, c := range []struct{ text, blob string }{{goldenStatic, goldenStaticBlob}, {goldenDynamic, goldenDynBlob}} {
		tp, err := Parse(c.text)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := tp.MarshalBinary()
		if hex.EncodeToString(b) != c.blob {
			t.Fatalf("binary encoding changed for %s", c.text)
		}
		raw, _ := hex.DecodeString(c.blob)
		d, err := Decode(raw)
		if err != nil || d.Text() != c.text {
			t.Fatalf("released blob no longer decodes: %v", err)
		}
	}
}

// Every method must be safe on nil and on the zero value: a missing or
// default-constructed Template is an error, never a panic.
func TestZeroAndNilTemplates(t *testing.T) {
	for _, tp := range []*Template{nil, {}} {
		_ = tp.String()
		_ = tp.GoString()
		_ = tp.Text()
		_ = tp.IsDynamic()
		_ = tp.VerifyCRC()
		if _, ok := tp.Amount(); ok {
			t.Error("amount from empty template")
		}
		if _, ok := tp.Value(1); ok {
			t.Error("value from empty template")
		}
		if _, ok := tp.SubValue(1); ok {
			t.Error("subvalue from empty template")
		}
		if _, err := tp.MarshalBinary(); err == nil {
			t.Error("marshal of empty template succeeded")
		}
		if _, err := tp.AppendBinary(nil); err == nil {
			t.Error("append of empty template succeeded")
		}
		if _, err := tp.Generate(GenerateRequest{Amount: "1", Reference: "R", DerivationAuthorized: true}); err == nil {
			t.Error("generate from empty template succeeded")
		}
	}
}

// The codec is standard-library only: no third-party code, and never the
// payment SDK, so adopting it adds nothing to a dependency graph.
func TestStandardLibraryOnly(t *testing.T) {
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mod), "require") {
		t.Error("go.mod must not require any module")
	}
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if p == "github.com/nokibsarkar/go-banglaqr" {
				continue // external example tests import the package itself
			}
			if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") {
				t.Errorf("%s imports non-standard-library package %s", f, p)
			}
		}
	}
}
