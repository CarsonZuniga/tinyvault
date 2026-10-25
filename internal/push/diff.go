package push

import (
	"fmt"
	"maps"
	"slices"

	"github.com/carsonzuniga/tinyvault/internal/formats"
)

type Preview struct {
	Missing, Unparsed       bool
	Added, Changed, Removed []string
}

func (pv Preview) String() string {
	switch {
	case pv.Unparsed:
		return "cannot parse remote file"
	case pv.Missing:
		return string(Missing)
	}
	return fmt.Sprintf("%d added, %d changed, %d removed", len(pv.Added), len(pv.Changed), len(pv.Removed))
}

func (p *Pusher) Preview(project, env, target, actor string) (Preview, error) {
	t, body, err := p.export(project, env, target, actor, "preview "+target)
	if err != nil {
		return Preview{}, err
	}
	want, err := formats.Parse(t.Format, string(body))
	if err != nil {
		return Preview{}, err
	}
	c, err := p.connect(project, env, t, actor)
	if err != nil {
		return Preview{}, err
	}
	defer c.Close()
	remote, found, err := readFile(c, t.Path)
	if err != nil {
		return Preview{}, &RemoteError{err}
	}
	pv := preview(remote, found, t.Format, want)
	if err := p.st.Audit(actor, "target.preview", project+"/"+env+"/"+t.Name, pv.String()); err != nil {
		return Preview{}, err
	}
	return pv, nil
}

func preview(remote []byte, found bool, format string, want map[string]string) Preview {
	have := map[string]string{}
	if found {
		var err error
		if have, err = formats.Parse(format, string(remote)); err != nil {
			return Preview{Unparsed: true}
		}
	}
	pv := Preview{Missing: !found}
	for _, k := range slices.Sorted(maps.Keys(want)) {
		v, ok := have[k]
		switch {
		case !ok:
			pv.Added = append(pv.Added, k)
		case v != want[k]:
			pv.Changed = append(pv.Changed, k)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(have)) {
		if _, ok := want[k]; !ok {
			pv.Removed = append(pv.Removed, k)
		}
	}
	return pv
}
