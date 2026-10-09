package formats

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var keyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

func ValidKey(k string) bool { return keyRe.MatchString(k) }

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func ParseDotenv(s string) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || !ValidKey(k) {
			return nil, fmt.Errorf("line %d: invalid entry", n)
		}
		v = strings.TrimSpace(v)
		switch {
		case len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"':
			v = v[1 : len(v)-1]
			v = strings.NewReplacer(`\n`, "\n", `\"`, `"`, `\\`, `\`).Replace(v)
		case len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'':
			v = v[1 : len(v)-1]
		default:
			if i := strings.Index(v, " #"); i >= 0 {
				v = strings.TrimSpace(v[:i])
			}
		}
		out[k] = v
	}
	return out, sc.Err()
}

func ExportDotenv(m map[string]string) string {
	var b strings.Builder
	for _, k := range sortedKeys(m) {
		v := m[k]
		if strings.ContainsAny(v, " #\"'\\\n$") || v == "" {
			v = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v) + `"`
		}
		fmt.Fprintf(&b, "%s=%s\n", k, v)
	}
	return b.String()
}

func ParseJSON(s string) (map[string]string, error) {
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, err
	}
	for k := range m {
		if !ValidKey(k) {
			return nil, fmt.Errorf("invalid key %q", k)
		}
	}
	return m, nil
}

func ExportJSON(m map[string]string) string {
	b, _ := json.MarshalIndent(m, "", "  ")
	return string(b) + "\n"
}

func ExportShell(m map[string]string) string {
	var b strings.Builder
	for _, k := range sortedKeys(m) {
		fmt.Fprintf(&b, "export %s='%s'\n", k, strings.ReplaceAll(m[k], "'", `'\''`))
	}
	return b.String()
}

func ExportDockerSecrets(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func ExportK8sSecret(name, namespace string, m map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n  namespace: %s\ntype: Opaque\ndata:\n", name, namespace)
	for _, k := range sortedKeys(m) {
		fmt.Fprintf(&b, "  %s: %s\n", k, base64.StdEncoding.EncodeToString([]byte(m[k])))
	}
	return b.String()
}

// Minimal line-based parser to stay dependency-free; swap for yaml.v3 later.
func ParseK8sSecret(s string) (map[string]string, error) {
	out := map[string]string{}
	section := ""
	for _, raw := range strings.Split(s, "\n") {
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		if !strings.HasPrefix(raw, " ") {
			section = strings.TrimSuffix(strings.TrimSpace(raw), ":")
			continue
		}
		if section != "data" && section != "stringData" {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(raw), ":")
		if !ok || !ValidKey(strings.TrimSpace(k)) {
			return nil, fmt.Errorf("bad entry %q", raw)
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if section == "data" {
			d, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, fmt.Errorf("key %s: bad base64", k)
			}
			v = string(d)
		}
		out[strings.TrimSpace(k)] = v
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no data found")
	}
	return out, nil
}

var refRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_.-]*)\}`)

func Resolve(m map[string]string) (map[string]string, error) {
	out := map[string]string{}
	var expand func(k string, stack []string) (string, error)
	expand = func(k string, stack []string) (string, error) {
		for _, s := range stack {
			if s == k {
				return "", fmt.Errorf("reference cycle: %s -> %s", strings.Join(stack, " -> "), k)
			}
		}
		if v, ok := out[k]; ok {
			return v, nil
		}
		raw, ok := m[k]
		if !ok {
			return "", fmt.Errorf("unknown reference ${%s}", k)
		}
		var err error
		res := refRe.ReplaceAllStringFunc(raw, func(ref string) string {
			if err != nil {
				return ref
			}
			var v string
			v, err = expand(refRe.FindStringSubmatch(ref)[1], append(stack, k))
			return v
		})
		if err != nil {
			return "", err
		}
		out[k] = res
		return res, nil
	}
	for k := range m {
		if _, err := expand(k, nil); err != nil {
			return nil, err
		}
	}
	return out, nil
}
