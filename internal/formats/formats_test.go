package formats

import (
	"strings"
	"testing"
)

func TestDotenvRoundTrip(t *testing.T) {
	in := map[string]string{"A": "plain", "B": "has space", "C": `q"uote`, "D": "multi\nline", "E": ""}
	out, err := ParseDotenv(ExportDotenv(in))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range in {
		if out[k] != v {
			t.Errorf("%s: got %q want %q", k, out[k], v)
		}
	}
}

func TestParseDotenvStyles(t *testing.T) {
	m, err := ParseDotenv("# c\nexport A=1\nB='x y'\nC=val # trailing\n")
	if err != nil || m["A"] != "1" || m["B"] != "x y" || m["C"] != "val" {
		t.Fatalf("%v %v", m, err)
	}
	if _, err := ParseDotenv("bad line"); err == nil {
		t.Fatal("expected error")
	}
}

func TestK8sRoundTrip(t *testing.T) {
	in := map[string]string{"TOKEN": "abc123", "PASS": "p@ss"}
	out, err := ParseK8sSecret(ExportK8sSecret("s", "default", in))
	if err != nil || out["TOKEN"] != "abc123" || out["PASS"] != "p@ss" {
		t.Fatalf("%v %v", out, err)
	}
}

func TestShellEscapesQuotes(t *testing.T) {
	s := ExportShell(map[string]string{"X": "it's $(rm -rf /)"})
	if !strings.Contains(s, `'it'\''s $(rm -rf /)'`) {
		t.Fatal(s)
	}
}

func TestResolve(t *testing.T) {
	m, err := Resolve(map[string]string{"HOST": "db", "URL": "pg://${HOST}:5432"})
	if err != nil || m["URL"] != "pg://db:5432" {
		t.Fatalf("%v %v", m, err)
	}
	if _, err := Resolve(map[string]string{"A": "${B}", "B": "${A}"}); err == nil {
		t.Fatal("cycle not detected")
	}
	if _, err := Resolve(map[string]string{"A": "${NOPE}"}); err == nil {
		t.Fatal("unknown ref not detected")
	}
}
