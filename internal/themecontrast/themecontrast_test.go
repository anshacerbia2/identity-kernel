package themecontrast

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

const stylesheet = "../../themes/scnehaux/login/resources/css/scnehaux.css"

// The WCAG 2.2 AA minimums STD-GLB-FE-009 §3.3 sets: SC 1.4.3 for text at the sizes this page uses
// (none is large-scale), SC 1.4.11 for the edge that identifies a field and for the focus indicator.
const (
	text = 4.5
	ui   = 3.0
)

// pair is a foreground over a background, each named by the surface it is composited from.
type pair struct {
	what       string
	foreground string
	background string
	minimum    float64
}

// The pairs the login pages draw. A background is "panel" (the translucent panel over the canvas),
// "field" (a field's sunken fill over the panel), or a token composited over the panel.
var pairs = []pair{
	{"heading and label", "--ds-color-neutral-text-strong-default", "panel", text},
	{"body text", "--ds-color-neutral-text-default-default", "panel", text},
	{"helper and footer text", "--ds-color-neutral-text-subtle-default", "panel", text},
	{"link", "--ds-color-primary-text-default-default", "panel", text},
	{"field error message", "--ds-color-danger-text-default-default", "panel", text},
	{"typed text", "--ds-color-neutral-text-strong-default", "field", text},
	{"primary button label", "--ds-color-primary-text-contrast-default", "--scnx-login-action-solid", text},
	{"primary button label, hover", "--ds-color-primary-text-contrast-default", "--scnx-login-action-hover", text},
	{"primary button label, pressed", "--ds-color-primary-text-contrast-default", "--scnx-login-action-pressed", text},
	{"secondary button label", "--ds-color-neutral-text-strong-default", "--ds-color-neutral-surface-subtle-default", text},
	{"secondary button label, hover", "--ds-color-neutral-text-strong-default", "--ds-color-neutral-surface-default-hover", text},
	{"authenticator choice description", "--ds-color-neutral-text-subtle-default", "--ds-color-neutral-surface-subtle-default", text},
	{"danger message", "--ds-color-danger-text-default-default", "--ds-color-danger-surface-subtle-default", text},
	{"warning message", "--ds-color-warning-text-default-default", "--ds-color-warning-surface-subtle-default", text},
	{"success message", "--ds-color-success-text-default-default", "--ds-color-success-surface-subtle-default", text},
	{"info message", "--ds-color-info-text-default-default", "--ds-color-info-surface-subtle-default", text},
	{"field edge against the panel", "--scnx-login-control-border", "panel", ui},
	{"field edge against its fill", "--scnx-login-control-border", "field", ui},
	{"invalid field edge", "--ds-color-danger-solid-default-default", "panel", ui},
	{"focus indicator", "--scnx-login-focus", "panel", ui},
}

// The canvas a panel can sit over: the plain canvas, and the canvas under each aurora at full
// strength, where it differs most from the plain one.
var backdrops = []struct {
	name   string
	layers []string
}{
	{"canvas", nil},
	{"canvas under the first aurora", []string{"--ds-color-neutral-canvas-glow-a"}},
	{"canvas under both auroras", []string{"--ds-color-neutral-canvas-glow-a", "--ds-color-neutral-canvas-glow-b"}},
}

func TestEveryPairMeetsWCAG22AAInBothSchemes(t *testing.T) {
	css, err := os.ReadFile(stylesheet)
	if err != nil {
		t.Fatal(err)
	}
	light, dark := Schemes(string(css))
	var report strings.Builder
	for _, scheme := range []struct {
		name   string
		tokens Scheme
	}{{"light", light}, {"dark", dark}} {
		colour := func(name string) Colour {
			c, err := scheme.tokens.Colour(name)
			if err != nil {
				t.Fatalf("%s: %v", scheme.name, err)
			}
			return c
		}
		for _, p := range pairs {
			worst, where := 0.0, ""
			for _, b := range backdrops {
				canvas := colour("--ds-color-neutral-canvas-default")
				for _, layer := range b.layers {
					canvas = Over(colour(layer), canvas)
				}
				panel := Over(colour("--ds-color-neutral-surface-raised-default"), canvas)
				surface := func(name string) Colour {
					switch name {
					case "panel":
						return panel
					case "field":
						return Over(colour("--ds-color-neutral-surface-sunken-default"), panel)
					}
					return Over(colour(name), panel)
				}
				bg := surface(p.background)
				fg := Over(colour(p.foreground), bg)
				if r := Ratio(fg, bg); worst == 0 || r < worst {
					worst, where = r, fmt.Sprintf("%s on %s over the %s", Hex(fg), Hex(bg), b.name)
				}
			}
			fmt.Fprintf(&report, "%-6s %-36s %5.2f:1 (%s)\n", scheme.name, p.what, worst, where)
			if worst < p.minimum {
				t.Errorf("%s, %s: %.2f:1, under %.1f:1: %s", scheme.name, p.what, worst, p.minimum, where)
			}
		}
	}
	t.Logf("the worst case of each pair:\n%s", report.String())
}

func TestTheSchemesAreReadAsTheCascadeResolvesThem(t *testing.T) {
	light, dark := Schemes(`
:root { --a: oklch(0.5 0 0); --b: var(--a); }
:root.pf-v5-theme-dark { --a: oklch(0.9 0 0); }
@media (prefers-contrast: more) { :root.pf-v5-theme-dark { --a: oklch(1 0 0); } }
`)
	l, err := light.Colour("--b")
	if err != nil {
		t.Fatal(err)
	}
	d, err := dark.Colour("--b")
	if err != nil {
		t.Fatal(err)
	}
	if Hex(l) == Hex(d) {
		t.Errorf("the dark scheme did not overlay the light one: both %s", Hex(l))
	}
	if Hex(d) == Hex(OKLCH(1, 0, 0, 1)) {
		t.Errorf("a rule inside @media was read")
	}
}

func TestRatioMatchesWCAGsWorkedValues(t *testing.T) {
	black, white := Colour{0, 0, 0, 1}, Colour{1, 1, 1, 1}
	if r := Ratio(black, white); r < 20.99 || r > 21.01 {
		t.Errorf("black on white is %.2f:1, want 21:1", r)
	}
	// #767676 on white is the grey WCAG's understanding documents give as passing 4.5:1.
	grey := Colour{0x76 / 255.0, 0x76 / 255.0, 0x76 / 255.0, 1}
	if r := Ratio(grey, white); r < 4.5 || r > 4.6 {
		t.Errorf("#767676 on white is %.2f:1, want 4.54:1", r)
	}
}
