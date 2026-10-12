// Package themecontrast measures the login theme's colour pairs the way WCAG 2.2 measures them, from
// the tokens its stylesheet declares (TDD-identity-kernel-004 §Visual Language).
//
// The theme's surfaces are translucent over a gradient canvas, so no pair can be read off the
// stylesheet: the colour behind a word is the panel composited over whatever part of the canvas it
// sits on. STD-GLB-FE-009 §3.3 asks for exactly that: "Tests use actual foreground/background pairs
// after alpha composition in each supported theme and state." The package reads the custom
// properties of each scheme, converts OKLCH to sRGB, composites, and returns the WCAG contrast ratio.
package themecontrast

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Colour is an sRGB colour with straight alpha, each channel in [0, 1].
type Colour struct{ R, G, B, A float64 }

// Scheme is one colour scheme's custom properties, by name without the leading dashes' prefix kept:
// "--ds-color-neutral-canvas-default".
type Scheme map[string]string

var (
	comments = regexp.MustCompile(`(?s)/\*.*?\*/`)
	rule     = regexp.MustCompile(`(?s)([^{}]+)\{([^{}]*)\}`)
	varRef   = regexp.MustCompile(`^var\((--[A-Za-z0-9-]+)\)$`)
	oklchFn  = regexp.MustCompile(`^oklch\(\s*([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s*(?:/\s*([0-9.]+)\s*)?\)$`)
)

// Schemes reads the stylesheet's custom properties for the light scheme (every top-level :root rule)
// and the dark one (the light scheme overlaid with :root.pf-v5-theme-dark), as the cascade resolves
// them on <html>. Rules inside @media blocks are not read: prefers-contrast is a third rendering
// this package does not measure.
func Schemes(css string) (light, dark Scheme) {
	css = comments.ReplaceAllString(css, "")
	css = stripAtBlocks(css)
	light, dark = Scheme{}, Scheme{}
	var darkOnly []Scheme
	for _, m := range rule.FindAllStringSubmatch(css, -1) {
		selector := strings.TrimSpace(m[1])
		decls := declarations(m[2])
		switch selector {
		case ":root":
			for k, v := range decls {
				light[k] = v
			}
		case ":root.pf-v5-theme-dark":
			darkOnly = append(darkOnly, decls)
		}
	}
	for k, v := range light {
		dark[k] = v
	}
	for _, d := range darkOnly {
		for k, v := range d {
			dark[k] = v
		}
	}
	return light, dark
}

// stripAtBlocks removes every @-rule with a block (@media, @font-face), whose nesting the rule
// pattern cannot follow.
func stripAtBlocks(css string) string {
	var out strings.Builder
	for i := 0; i < len(css); i++ {
		if css[i] != '@' {
			out.WriteByte(css[i])
			continue
		}
		open := strings.IndexByte(css[i:], '{')
		semi := strings.IndexByte(css[i:], ';')
		if open < 0 || (semi >= 0 && semi < open) {
			out.WriteByte(css[i])
			continue
		}
		depth := 0
		j := i + open
		for ; j < len(css); j++ {
			if css[j] == '{' {
				depth++
			} else if css[j] == '}' {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		i = j
	}
	return out.String()
}

func declarations(body string) map[string]string {
	out := map[string]string{}
	for _, d := range strings.Split(body, ";") {
		name, value, ok := strings.Cut(d, ":")
		name = strings.TrimSpace(name)
		if !ok || !strings.HasPrefix(name, "--") {
			continue
		}
		out[name] = strings.Join(strings.Fields(value), " ")
	}
	return out
}

// Colour resolves a custom property to a colour, following var() references.
func (s Scheme) Colour(name string) (Colour, error) {
	value, seen := name, map[string]bool{}
	for {
		v, ok := s[value]
		if !ok {
			return Colour{}, fmt.Errorf("%s is not declared", value)
		}
		if m := varRef.FindStringSubmatch(v); m != nil {
			if seen[m[1]] {
				return Colour{}, fmt.Errorf("%s refers to itself", name)
			}
			seen[m[1]] = true
			value = m[1]
			continue
		}
		return parseOKLCH(v)
	}
}

func parseOKLCH(v string) (Colour, error) {
	m := oklchFn.FindStringSubmatch(v)
	if m == nil {
		return Colour{}, fmt.Errorf("%q is not an oklch() colour", v)
	}
	l, _ := strconv.ParseFloat(m[1], 64)
	c, _ := strconv.ParseFloat(m[2], 64)
	h, _ := strconv.ParseFloat(m[3], 64)
	a := 1.0
	if m[4] != "" {
		a, _ = strconv.ParseFloat(m[4], 64)
	}
	return OKLCH(l, c, h, a), nil
}

// OKLCH converts an OKLCH colour to sRGB (Björn Ottosson's OKLab matrices, as CSS Color 4 cites
// them), clipping each channel to the gamut.
func OKLCH(l, c, h, alpha float64) Colour {
	hr := h * math.Pi / 180
	a, b := c*math.Cos(hr), c*math.Sin(hr)
	l_ := l + 0.3963377774*a + 0.2158037573*b
	m_ := l - 0.1055613458*a - 0.0638541728*b
	s_ := l - 0.0894841775*a - 1.2914855480*b
	L, M, S := l_*l_*l_, m_*m_*m_, s_*s_*s_
	r := 4.0767416621*L - 3.3077115913*M + 0.2309699292*S
	g := -1.2684380046*L + 2.6097574011*M - 0.3413193965*S
	bl := -0.0041960863*L - 0.7034186147*M + 1.7076147010*S
	return Colour{encode(r), encode(g), encode(bl), alpha}
}

func encode(x float64) float64 {
	x = math.Min(math.Max(x, 0), 1)
	if x <= 0.0031308 {
		return 12.92 * x
	}
	return 1.055*math.Pow(x, 1/2.4) - 0.055
}

// Over composites top over an opaque bottom.
func Over(top, bottom Colour) Colour {
	a := top.A
	return Colour{top.R*a + bottom.R*(1-a), top.G*a + bottom.G*(1-a), top.B*a + bottom.B*(1-a), 1}
}

// Ratio is the WCAG 2.2 contrast ratio of two opaque colours.
func Ratio(x, y Colour) float64 {
	lx, ly := luminance(x), luminance(y)
	if lx < ly {
		lx, ly = ly, lx
	}
	return (lx + 0.05) / (ly + 0.05)
}

func luminance(c Colour) float64 {
	lin := func(v float64) float64 {
		if v <= 0.04045 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(c.R) + 0.7152*lin(c.G) + 0.0722*lin(c.B)
}

// Hex writes an opaque colour as #rrggbb, for messages.
func Hex(c Colour) string {
	return fmt.Sprintf("#%02x%02x%02x", int(math.Round(c.R*255)), int(math.Round(c.G*255)), int(math.Round(c.B*255)))
}
