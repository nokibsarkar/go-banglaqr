package banglaqr

import (
	"bytes"
	"flag"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var updateAPI = flag.Bool("update-api", false, "rewrite testdata/api.txt")

// TestPublicAPIIsPinned fails when the exported API changes, so every change is
// a deliberate decision: additions are compatible (regenerate the snapshot with
// -update-api and note it in CHANGELOG.md); removals or signature changes are
// breaking and require a new major version.
func TestPublicAPIIsPinned(t *testing.T) {
	got := exportedAPI(t)
	if *updateAPI {
		if err := os.WriteFile("testdata/api.txt", []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile("testdata/api.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("exported API changed; review for compatibility, then run: go test -run TestPublicAPIIsPinned -update-api\n--- want\n%s\n--- got\n%s", want, got)
	}
}

func exportedAPI(t *testing.T) string {
	t.Helper()
	fset := token.NewFileSet()
	files, _ := filepath.Glob("*.go")
	var lines []string
	node := func(n ast.Node) string {
		var b bytes.Buffer
		if err := printer.Fprint(&b, fset, n); err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(b.String()), " ")
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				recv := ""
				if d.Recv != nil {
					r := node(d.Recv.List[0].Type)
					if !ast.IsExported(strings.TrimPrefix(r, "*")) {
						continue
					}
					recv = "(" + r + ") "
				}
				lines = append(lines, "func "+recv+d.Name.Name+strings.TrimPrefix(node(d.Type), "func"))
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						if !s.Name.IsExported() {
							continue
						}
						if st, ok := s.Type.(*ast.StructType); ok {
							lines = append(lines, "type "+s.Name.Name+" struct")
							for _, fl := range st.Fields.List {
								for _, n := range fl.Names {
									if n.IsExported() {
										lines = append(lines, "field "+s.Name.Name+"."+n.Name+" "+node(fl.Type))
									}
								}
							}
							continue
						}
						lines = append(lines, "type "+s.Name.Name+" "+node(s.Type))
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.IsExported() {
								lines = append(lines, d.Tok.String()+" "+n.Name)
							}
						}
					}
				}
			}
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}
