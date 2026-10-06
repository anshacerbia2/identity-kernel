// Command theme-overrides proves every template the scnehaux theme copies against the themes jar of
// the release the image runs (TDD-identity-kernel-004 §Override Surface): each copy is the stock
// keycloak.v2 template with exactly the replacements themes/overrides.json declares.
//
//	theme-overrides -jar org.keycloak.keycloak-themes-26.7.5.jar           # check
//	theme-overrides -jar org.keycloak.keycloak-themes-26.8.0.jar -write    # make the copies again
//
// -write is for a release upgrade: it makes each copy from the new release's template with the same
// replacements, and writes nothing when a replacement no longer finds its stock text. That is the
// release changing or fixing what the copy changes, which a person decides.
//
// Exit status: 0 every copy holds, 1 a finding or an error.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/anshacerbia2/identity-kernel/internal/themecheck"
)

func main() {
	jarPath := flag.String("jar", "", "the release's org.keycloak.keycloak-themes jar, read from the kernel image")
	theme := flag.String("theme", "themes/scnehaux", "the theme directory")
	manifestPath := flag.String("manifest", "themes/overrides.json", "the declared overrides")
	write := flag.Bool("write", false, "make every copy again from the release's templates")
	flag.Parse()
	if *jarPath == "" {
		fmt.Fprintln(os.Stderr, "theme-overrides: -jar is required")
		os.Exit(1)
	}

	manifest, err := themecheck.LoadManifest(*manifestPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "theme-overrides:", err)
		os.Exit(1)
	}
	jar, err := themecheck.OpenJar(*jarPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "theme-overrides:", err)
		os.Exit(1)
	}
	defer func() { _ = jar.Close() }()

	var findings []error
	if *write {
		findings = themecheck.Write(*theme, manifest, &jar.Reader)
	}
	if len(findings) == 0 {
		findings = themecheck.Check(os.DirFS(*theme), manifest, &jar.Reader)
	}
	for _, finding := range findings {
		fmt.Fprintln(os.Stderr, "theme-overrides:", finding)
	}
	if len(findings) > 0 {
		os.Exit(1)
	}
	for _, o := range manifest.Overrides {
		fmt.Printf("%s: the release's template with %d declared replacement(s) (%s)\n", o.Template,
			len(o.Replacements), o.Upstream)
	}
}
