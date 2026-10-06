package themecheck

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

const stock = `<label for="form-vertical-name">Code</label>
<input id="totp">
`

func jar(t *testing.T, files map[string]string) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte(content))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func manifest() Manifest {
	return Manifest{Overrides: []Override{{
		Template: "login/x.ftl", Reason: "no accessible name", Upstream: "keycloak#1",
		Replacements: []Replacement{{Old: `for="form-vertical-name"`, New: `for="totp"`}},
	}}}
}

func fixed() string { return strings.Replace(stock, `for="form-vertical-name"`, `for="totp"`, 1) }

func TestACopyThatIsTheStockTemplateWithItsReplacementsPasses(t *testing.T) {
	theme := fstest.MapFS{"login/x.ftl": {Data: []byte(fixed())}}
	if findings := Check(theme, manifest(), jar(t, map[string]string{Parent + "login/x.ftl": stock})); len(findings) > 0 {
		t.Errorf("findings: %v", findings)
	}
}

func TestEveryDivergenceIsAFinding(t *testing.T) {
	for name, c := range map[string]struct {
		theme    fstest.MapFS
		manifest Manifest
		stock    map[string]string
	}{
		"an undeclared copy": {
			theme:    fstest.MapFS{"login/x.ftl": {Data: []byte(fixed())}, "login/y.ftl": {Data: []byte("y")}},
			manifest: manifest(), stock: map[string]string{Parent + "login/x.ftl": stock},
		},
		"a declared copy that is missing": {
			theme: fstest.MapFS{}, manifest: manifest(), stock: map[string]string{Parent + "login/x.ftl": stock},
		},
		"a change the manifest does not declare": {
			theme:    fstest.MapFS{"login/x.ftl": {Data: []byte(fixed() + "<script>")}},
			manifest: manifest(), stock: map[string]string{Parent + "login/x.ftl": stock},
		},
		"the release fixed it": {
			theme:    fstest.MapFS{"login/x.ftl": {Data: []byte(fixed())}},
			manifest: manifest(), stock: map[string]string{Parent + "login/x.ftl": fixed()},
		},
		"the release dropped the template": {
			theme: fstest.MapFS{"login/x.ftl": {Data: []byte(fixed())}}, manifest: manifest(), stock: map[string]string{},
		},
		"no reason": {
			theme: fstest.MapFS{"login/x.ftl": {Data: []byte(fixed())}},
			manifest: Manifest{Overrides: []Override{{Template: "login/x.ftl", Upstream: "keycloak#1",
				Replacements: manifest().Overrides[0].Replacements}}},
			stock: map[string]string{Parent + "login/x.ftl": stock},
		},
	} {
		if findings := Check(c.theme, c.manifest, jar(t, c.stock)); len(findings) == 0 {
			t.Errorf("%s: no finding", name)
		}
	}
}

// Write makes the copy from a new release's template, and writes nothing when a replacement no
// longer finds its stock text.
func TestWriteMakesTheCopyAgainOnlyWhenEveryReplacementApplies(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "login"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "login", "x.ftl")
	if err := os.WriteFile(path, []byte("old copy"), 0o644); err != nil {
		t.Fatal(err)
	}
	newRelease := stock + "<p>a new release</p>\n"
	if problems := Write(dir, manifest(), jar(t, map[string]string{Parent + "login/x.ftl": newRelease})); len(problems) > 0 {
		t.Fatalf("problems: %v", problems)
	}
	got, _ := os.ReadFile(path)
	if want := strings.Replace(newRelease, `for="form-vertical-name"`, `for="totp"`, 1); string(got) != want {
		t.Errorf("the copy is %q, want %q", got, want)
	}

	if problems := Write(dir, manifest(), jar(t, map[string]string{Parent + "login/x.ftl": fixed()})); len(problems) == 0 {
		t.Error("a release that fixed the template was written over")
	}
	if after, _ := os.ReadFile(path); string(after) != string(got) {
		t.Error("a refused write changed the copy")
	}
}
