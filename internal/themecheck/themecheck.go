// Package themecheck proves the scnehaux theme's copied templates against the release they were
// copied from (TDD-identity-kernel-004 §Override Surface, ADR-IAM-001 §5.7).
//
// A copied template no longer receives the kernel's changes. So each copy is declared in
// themes/overrides.json as the stock keycloak.v2 template with a list of exact replacements, and the
// check rebuilds it from the stock template in the image's themes jar. A release that changes the
// template around a replacement, or fixes what the copy fixes, makes the stock text unfindable, and
// the check fails until the copy is made again or removed.
package themecheck

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Parent is where the jar keeps the theme the scnehaux theme extends.
const Parent = "theme/keycloak.v2/"

// Manifest is themes/overrides.json.
type Manifest struct {
	Overrides []Override `json:"overrides"`
}

// Override is one copied template, relative to the theme: login/login-config-totp.ftl.
type Override struct {
	Template     string        `json:"template"`
	Reason       string        `json:"reason"`
	Upstream     string        `json:"upstream"`
	RemoveWhen   string        `json:"remove_when"`
	Replacements []Replacement `json:"replacements"`
}

// Replacement is one exact edit to the stock template; Old occurs in it exactly once.
type Replacement struct {
	Old string `json:"old"`
	New string `json:"new"`
}

// LoadManifest reads and parses the manifest.
func LoadManifest(path string) (Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// Check compares every template in theme with the manifest and the stock templates in themes, the
// release's themes jar. It returns every finding, not only the first.
func Check(theme fs.FS, manifest Manifest, themes *zip.Reader) []error {
	var findings []error
	declared := map[string]Override{}
	for _, o := range manifest.Overrides {
		if _, repeated := declared[o.Template]; repeated {
			findings = append(findings, fmt.Errorf("%s is declared twice", o.Template))
		}
		declared[o.Template] = o
	}

	copied := map[string]bool{}
	_ = fs.WalkDir(theme, ".", func(path string, entry fs.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && strings.HasSuffix(path, ".ftl") {
			copied[path] = true
		}
		return nil
	})
	for _, path := range sortedKeys(copied) {
		if _, ok := declared[path]; !ok {
			findings = append(findings, fmt.Errorf("%s is a copied template themes/overrides.json does not declare, "+
				"with no reason and no replacements to prove it by", path))
		}
	}

	for _, path := range sortedKeys(declared) {
		o := declared[path]
		if !copied[path] {
			findings = append(findings, fmt.Errorf("%s is declared and not in the theme", path))
			continue
		}
		if strings.TrimSpace(o.Reason) == "" || strings.TrimSpace(o.Upstream) == "" || len(o.Replacements) == 0 {
			findings = append(findings, fmt.Errorf("%s needs a reason, an upstream reference and at least one "+
				"replacement", path))
			continue
		}
		want, problems := Rebuild(o, themes)
		if len(problems) > 0 {
			findings = append(findings, problems...)
			continue
		}
		got, err := fs.ReadFile(theme, path)
		if err != nil {
			findings = append(findings, err)
			continue
		}
		if string(got) != want {
			findings = append(findings, fmt.Errorf("%s differs from the release's template with its declared "+
				"replacements; a copy carries no change the manifest does not declare", path))
		}
	}
	return findings
}

// Rebuild is the copy an override declares: the release's stock template with each replacement
// applied, every replacement's stock text found exactly once.
func Rebuild(o Override, themes *zip.Reader) (string, []error) {
	stock, err := readZip(themes, Parent+o.Template)
	if err != nil {
		return "", []error{fmt.Errorf("%s: the release has no stock template to prove the copy by: %w", o.Template, err)}
	}
	var problems []error
	want := stock
	for i, r := range o.Replacements {
		if n := strings.Count(stock, r.Old); n != 1 {
			problems = append(problems, fmt.Errorf("%s: replacement %d finds its stock text %d times in the release, "+
				"not once; the release changed or fixed the template, so revise the replacement or remove the copy (%s)",
				o.Template, i+1, n, o.Upstream))
			continue
		}
		want = strings.Replace(want, r.Old, r.New, 1)
	}
	return want, problems
}

// Write makes every declared copy again from the release's stock template, for a release upgrade.
// It writes nothing when any replacement no longer applies.
func Write(themeDir string, manifest Manifest, themes *zip.Reader) []error {
	copies := map[string]string{}
	var problems []error
	for _, o := range manifest.Overrides {
		want, p := Rebuild(o, themes)
		problems = append(problems, p...)
		copies[o.Template] = want
	}
	if len(problems) > 0 {
		return problems
	}
	for _, path := range sortedKeys(copies) {
		target := filepath.Join(themeDir, filepath.FromSlash(path))
		if err := os.WriteFile(target, []byte(copies[path]), 0o644); err != nil {
			return []error{err}
		}
	}
	return nil
}

// OpenJar opens the release's themes jar.
func OpenJar(path string) (*zip.ReadCloser, error) {
	return zip.OpenReader(filepath.Clean(path))
}

func readZip(z *zip.Reader, name string) (string, error) {
	f, err := z.Open(name)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(f)
	return string(raw), err
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
