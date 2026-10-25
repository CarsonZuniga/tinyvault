package push

import (
	"slices"
	"testing"
)

func TestPreview(t *testing.T) {
	want := map[string]string{"A": "1", "B": "2", "C": "3"}
	pv := preview([]byte("A=1\nB=old\nD=4\n"), true, "dotenv", want)
	if !slices.Equal(pv.Added, []string{"C"}) || !slices.Equal(pv.Changed, []string{"B"}) || !slices.Equal(pv.Removed, []string{"D"}) {
		t.Fatalf("%+v", pv)
	}
	if pv := preview(nil, false, "dotenv", want); !pv.Missing || len(pv.Added) != 3 {
		t.Fatalf("missing: %+v", pv)
	}
	if pv := preview([]byte("not json"), true, "json", want); !pv.Unparsed || pv.Added != nil {
		t.Fatalf("unparsed: %+v", pv)
	}
}
