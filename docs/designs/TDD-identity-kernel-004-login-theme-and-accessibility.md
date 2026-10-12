---
doc_meta:
  id: TDD-identity-kernel-004
  title: Hosted Login Theme, Accessibility, and Disclosure Discipline
  owner: Identity Platform Team
  version: 1.7.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-11
  last_reviewed: 2026-10-12
  parent_sad: SAD-001
---

# Hosted Login Theme, Accessibility, and Disclosure Discipline

## Purpose

Specify the Keycloak theme that renders every authentication surface: what it overrides
and what it deliberately does not, how it stays accessible, and how it avoids telling an
unauthenticated visitor things they should not learn.

This theme realizes the hosted-login portion of SAD-002 while living in this repository,
because Keycloak renders it and its template contract is bound to the release that does
the rendering.

## Scope

**In scope**

- The override surface: which Keycloak templates are replaced and which are only styled.
- Accessibility conformance and why it is enforced hardest here.
- Account enumeration resistance in messages, timing, and status codes.
- Localization, and the disclosure risk it introduces.
- Browser security headers on unauthenticated pages.

**Out of scope**

- Account security management, administration, and the developer console — those are
  applications in `identity-experience`, reached after authentication.
- Authentication flow configuration, MFA policy, and recovery policy — realm
  configuration in `TDD-identity-kernel-001`.
- Design tokens and component semantics, owned by the UI Platform. Until it publishes them, the
  theme copies Identity Experience's stand-in for them (§Visual Language).
- The BFF session pattern — owned by `TDD-identity-experience-001`.

## Technical Context

Two properties make this surface different from every other page in the estate.

**It is the only page an unauthenticated attacker can always reach.** Every other
surface is behind a session. Whatever this page discloses, it discloses to anyone.

**It is the only page nobody can skip.** An inaccessible administration screen blocks
one task. An inaccessible login page blocks the platform, for that person, entirely.
PAD-PLT-001 §6.6 sets WCAG 2.2 AA for hosted identity experiences, and this is where
that target has no workaround.

A third property shapes the engineering rather than the security: **every template
override is an upgrade liability.** A Keycloak upgrade may change a template's
structure, its message keys, or the variables it exposes. An override is a fork of that
template frozen at the version it was copied from, and it will silently diverge.

## Component Design

### Override Surface

The rule is that styling is not overriding.

| Change needed | Mechanism | Upgrade cost |
| :-- | :-- | :-- |
| Colour, type, spacing, layout rhythm | CSS variables mapped from design tokens | None |
| Logo, favicon, product name | Theme properties and static assets | None |
| Message wording | `messages_*.properties` overrides | Low; a removed key is caught by the suite |
| Field order, added element, changed markup | Template override, `.ftl` | **High; re-verified every upgrade** |

A template is copied only when the required change cannot be made in CSS or in a
message bundle. Each override is listed in this design with the reason it exists, so
the upgrade suite knows what to re-verify and a future engineer knows what to try to
remove.

**As built (1.5.0): three templates are overridden, because a test showed the stock ones fail.** The
theme `scnehaux` names `keycloak.v2` as its parent, as ADR-IAM-001 §5.7 decides. Keycloak documents
the mechanism: "When extending a theme you can override individual resources (templates,
stylesheets, etc.)" (ADR-IAM-001 [R33]).

| Copied template | Its reason | Upstream | Removed when |
| :-- | :-- | :-- | :-- |
| `template.ftl` | The `username` macro labels the read-only field that shows who is signing in with `for="username"`. The field's id is `kc-attempted-username`, so on every page after the first (the one-time code, the passkey) the field has no accessible name (WCAG 2.2 1.3.1, 4.1.2). axe-core reports it as `label`, critical, in `browser/`. The copy renames the group to the field's id and changes nothing else | Not yet reported | The pinned release labels the field |
| `select-authenticator.ftl` | Each choice on the authenticator selection page is a `div` with `role="button"` and `tabindex="0"` that acts on click alone. A person without a pointer reaches it by Tab and cannot activate it (WCAG 2.2 2.1.1). The WAI-ARIA button pattern says "Enter: Activates the button" and "Space: Activates the button". The copy adds an `onkeydown` handler for both keys that does what the click does, and changes nothing else. The keyboard path in `browser/` found it; axe-core does not test activation | keycloak#45227 added the role and `tabindex`, not the handler | The pinned release activates a choice from the keyboard |
| `login-config-totp.ftl` | Both labels on the one-time-code enrolment page point at `form-vertical-name`, an id no element has. The code field and the device-name field are left with no accessible name (WCAG 2.2 1.3.1, 4.1.2). axe-core reports it as `label`, critical, in `browser/`. The copy changes the two `for` attributes and nothing else | keycloak#51206, open | The pinned release labels both fields |

A copy is declared in `themes/overrides.json` as the stock template plus a list of exact
replacements. `cmd/theme-overrides`, run by the `contract` job against the themes jar in the image,
rebuilds the copy from the release's own template and requires the result to equal the file.

- **A release that changes the template around a replacement fails.** The copy is then made again
  from the new template.
- **A release that fixes the bug fails.** The stock text is gone, and that failure is the signal to
  remove the copy.
- **A copy cannot carry a change the manifest does not declare.**

`cmd/theme-overrides -write` makes every copy again from a new release's templates with the same
replacements, so an upgrade that leaves the fixed text alone costs one command. It writes nothing
when a replacement no longer applies; whether the release fixed the bug or moved it is a person's
decision.

Version 1.0.0 planned five copied templates. None was copied until a test showed the stock template
cannot meet the requirement it was planned for:

| Planned override | Its reason | Status |
| :-- | :-- | :-- |
| `template.ftl` | language attribute | Met by the stock template, which writes `lang="${lang}"`; asserted in both locales |
| `template.ftl` | skip link | axe-core reports no `bypass` or landmark finding on any surface it scans; the copy above fixes a label, not this |
| `login.ftl` | unified identifier field, provider ordering | `loginWithEmailAllowed` gives one identifier field; there is no provider |
| `login-otp.ftl` | challenge copy, input semantics | Copy is a message bundle's; axe-core's one finding on the page is the `template.ftl` label |
| `login-reset-password.ftl` | enumeration-safe confirmation | Reset is not offered (`resetPasswordAllowed` false); recovery is a recovery code (ADR-IAM-005) |
| `error.ftl` | uniform error presentation | Wording is a message bundle's |

None of the planned overrides is copied. Copying one would freeze it at 26.7.5, and a protection the
kernel added to it later would not reach this page.

### Visual Language

**As built (1.7.0): the login pages look like Identity Experience's applications.** A person signs in
here and lands in Account, Administration or the Developer Console. The two should read as one
product. The theme therefore takes Identity Experience's visual language: its tokens, its canvas, its
panel, and its button, field and notice styles. It takes them by copying, not by depending on the
repository. Identity Experience holds them under a pending exception until the UI Platform publishes
`@scnx/system`. The kernel image is built from this repository alone, and the theme has no build step.

**Source.** The source is identity-experience at commit `b87b0998bbbc2c636642115ed48cc5b0a16f816f`, the
head of its pull request #54 (`light-theme-contrast`). That pull request gave Identity Experience the
accessible values this page first carried as departures (below). It is cited by its branch commit
until it merges; the citation then moves to the merge commit, with no value changing:

| Copied from | What |
| :-- | :-- |
| `packages/ui/src/styles/tokens/_ds-temporary.scss` | Every Tier-2 token the pages read, with the same name (ADR-UIP-TKN-003) and value, in both schemes: neutral canvas, surfaces, borders, text, icons and shadows; the primary, info, success, warning and danger schemes; spacing, radius, type scale, weights, motion |
| `packages/ui/src/styles/foundations/_base.scss` | The canvas: two radial auroras and a 2.5rem grid, drawn as gradients; selection colour; focus as an outline; links underlined; reduced motion; forced colours |
| `packages/ui/src/system/panel/Panel.module.scss` | The translucent panel, with an 18px backdrop blur and a hairline of light along its top edge |
| `packages/ui/src/system/button/Button.module.scss` | The primary and default buttons: radius, weight, the glow on hover |
| `packages/ui/src/system/field/Field.module.scss` | Labels, sunken fields with an opaque edge that darkens on hover, the danger edge of an invalid field, the error message in words beneath it |
| `packages/app-core/src/session/SignInNotice.module.scss` | Messages: a glyph and words on a tinted surface, never colour alone |
| `packages/app-core/src/shell/AppFrame.module.scss`, `apps/account/public/favicon.svg` | The brand: the shield mark in a tinted square, beside the name. The mark is the favicon too |
| `apps/account/package.json` (`@fontsource-variable/inter` 5.3.0) | Inter, the latin subset of its weight axis (48 KB), with its SIL Open Font License |

All of it is in `themes/scnehaux/login/resources/`: `css/scnehaux.css`, `fonts/` and `img/`.
`theme.properties` names the stylesheet after keycloak.v2's own and names the mark as the favicon.
No template changed for it.

**Before and after.**

| Element | keycloak.v2 (PatternFly 5), light / dark | Now, light / dark |
| :-- | :-- | :-- |
| Page background | Keycloak's background image / the same | Canvas `oklch(0.975 0.006 262)` / `oklch(0.145 0.02 262)`, with the two auroras and the grid |
| Card | `#fff` / `#1b1d21`, a 4px blue top border, `BoxShadow--xl` | `oklch(1 0 0 / 0.72)` / `oklch(0.19 0.024 262 / 0.62)` over the canvas, blurred; 1px border-subtle, radius 0.875rem, shadow-medium |
| Typeface | Red Hat Text and Display | Inter Variable, then `ui-sans-serif, system-ui` |
| Page title | `pf-m-3xl`, Red Hat Display | 1.75rem, weight 600, tracking -0.02em, text-strong |
| Primary button | `#06c` / `#1fa7f8`, radius 3px | `oklch(0.5 0.14 212)` / `oklch(0.8 0.14 212)`, radius 0.625rem, weight 600, a glow on hover |
| Secondary button | Transparent, blue text and edge | surface-subtle, text-strong, a border-default edge |
| Field | White / `#36373a`; an underline that thickens on focus | sunken `oklch(0.95 0.008 262 / 0.8)` / `oklch(0.12 0.018 262 / 0.7)`, radius 0.625rem, a whole opaque edge, border-strong `oklch(0.62 0.02 262)` / `oklch(0.55 0.02 262)` |
| Error message | Red helper text, a red top border on the alert | The danger scheme: `oklch(0.42 0.171 24)` / `oklch(0.86 0.171 24)` text on its 10% tint, a 45% edge |
| Focus | PatternFly's per-component focus | A 2px outline in border-default-focus (the primary solid), 2px off the element; in dark, `--ds-shadow-focus` adds a glow |
| Brand | The realm name, uppercase, 29px | The shield mark in a 2.5rem tinted square, beside the realm's display name, `Scnehaux`, in 1.25rem semibold |

**No departures.** Every `--ds-*` value in `scnehaux.css` equals Identity Experience's at the source
commit, in both schemes, and the page reads no colour of its own. Version 1.7.0 first carried four
departures, because Identity Experience's values then fell under WCAG 2.2 AA. An inaccessible login
page blocks the platform (§Technical Context). Identity Experience #54 adopted all four, so they are
now its tokens:

| Shared value | It was, in Identity Experience | Why |
| :-- | :-- | :-- |
| Light primary solid L 0.5, hover darkening to L 0.46, pressed L 0.44; the primary tints built from L 0.5 | L 0.55; hover lightened to L 0.6. Its label was 4.15:1, and 3.42:1 on hover | WCAG 2.2 SC 1.4.3: "The visual presentation of text and images of text has a contrast ratio of at least 4.5:1". The button label is 14px, not large-scale text. Now 5.06, 5.96 and 6.47:1 |
| `neutral-border-strong-default`, opaque: `oklch(0.62 0.02 262)` / `oklch(0.55 0.02 262)`. A field's edge, with `-hover` `oklch(0.48 0.02 262)` / `oklch(0.72 0.02 262)` | border-default, 16% alpha, 1.35:1 against the panel | SC 1.4.11 asks 3:1 of "Visual information required to identify user interface components and states". Its Understanding document: "Having a visual boundary indicating the hit area is only required when there is no other visual way to identify the presence of the control". An empty text field has no other way |
| Focus is an outline; `--ds-shadow-focus` is only the dark glow added to it, `none` in light | Button and Field removed the outline and drew a box-shadow ring | STD-GLB-FE-005 §3.9: "A shadow may add emphasis but never replaces the outline, because forced-colors mode computes `box-shadow` as `none`." |
| Links underlined | Undecorated | Told from the text around them by more than colour (SC 1.4.1, STD-GLB-FE-009 §3.3) |

STD-GLB-FE-009 §3.3 sets the thresholds: "Normal text meets WCAG 2.2 SC 1.4.3 at 4.5:1" and "User
interface components and meaningful graphical objects meet SC 1.4.11 at 3:1 against adjacent
colors." The stylesheet's only other custom properties are its alert's own (`--kc-alert-*`). Each
scheme sets them from `--ds-*` tokens, as Identity Experience's Button sets `--btn-*`.

**What stays Keycloak's.** The markup, PatternFly 5 and its Font Awesome glyphs are the kernel's, as
§Override Surface requires. The stylesheet points PatternFly's global variables at the tokens and
styles its components by class. It uses no cascade layers. PatternFly's stylesheet is unlayered, and an
unlayered rule beats every layered one. So the selectors start at `html.login-pf` and outrank
PatternFly's, and no rule needs `!important`.

- **The colour scheme follows the operating system.** keycloak.v2 puts `pf-v5-theme-dark` on the
  document when `prefers-color-scheme` is dark, and the dark tokens hang on that class. Identity
  Experience opens dark and offers a toggle that it keeps in its own origin's storage. The login page
  cannot read that storage, and a toggle here would be a script and a template change.
- **JetBrains Mono is not bundled.** The monospace stack falls back to `ui-monospace`, as Identity
  Experience's does before its font loads. It shows only the one-time-code key and the recovery codes.
- **The brand name is the realm's display name.** The realm declares `displayName` `Scnehaux`
  (TDD-identity-kernel-001 §Configuration), approved by the owner. It leaves `displayNameHtml` unset,
  so Keycloak renders the plain name, escaped, in the header and in the page title ("Sign in to
  Scnehaux"). The stylesheet changes no letter of it. The applications name themselves after it:
  "Scnehaux Account" and the rest.

**The accessibility fixes are kept.** The three copied templates (§Override Surface) and
`themes/overrides.json` are unchanged. They are `template.ftl`'s label for the attempted username,
`login-config-totp.ftl`'s two labels (keycloak#51206) and `select-authenticator.ftl`'s keyboard
handler (keycloak#45227). The labels, the `lang` attribute, the keyboard paths and the uniform failure
message are what `browser/` and `compat/` already assert.

**The Content Security Policy needs nothing new.** The stylesheet, the font and the mark come from the
kernel's own origin. `style-src 'self'` covers the first, `default-src 'self'` the font (the policy
names no `font-src`), and `img-src 'self'` the mark. The canvas is gradients, so no image is fetched.
No inline style or script was added.

**The QR code keeps a white quiet zone in the dark scheme.** A camera reads dark modules on light, so
the one-time-code enrolment's code sits on a white tile in both schemes.

**Contrast is computed, not assumed.** The surfaces are translucent over a gradient. No pair can be read
off the stylesheet, and axe-core reports what it cannot resolve as needing review, not as passing.
STD-GLB-FE-009 §3.3: "Tests use actual foreground/background pairs after alpha composition in each
supported theme and state." `internal/themecontrast` reads both schemes' tokens from `scnehaux.css`.
It composites each pair over the plain canvas and over each aurora at full strength, and requires
4.5:1 for text and 3:1 for a field's edge, the invalid edge and the focus indicator. The worst cases:

| Pair | Light | Dark |
| :-- | --: | --: |
| Helper and footer text on the panel | 5.97:1 | 6.90:1 |
| Primary button label (default, hover, pressed) | 5.06, 5.96, 6.47:1 | 10.66, 12.52, 8.77:1 |
| Authenticator choice description | 5.57:1 | 6.52:1 |
| Danger message on its tint | 7.25:1 | 7.77:1 |
| A field's edge against the panel, against its fill | 3.32, 3.18:1 | 3.53, 4.02:1 |
| Focus indicator against the panel | 4.82:1 | 9.58:1 |

The computation clips to sRGB per channel and leaves out the backdrop's 140% saturation and the grid,
whose lines are 5% opaque. It is evidence for the manual contrast check, not a replacement for it.

### Accessibility

Conformance targets WCAG 2.2 AA and is verified rather than asserted:

- Every input has a programmatically associated label; placeholder text is never the
  only label.
- Error messages are associated with their field and announced, so a screen reader
  reaches them without hunting.
- Focus order follows visual order, focus is always visible, and no focus trap exists.
- Contrast meets AA against the token palette in both themes.
- The flow is completable by keyboard alone, including provider selection, MFA, and
  recovery.
- Target sizes meet the 2.2 minimum, which matters on the recovery flow where people
  are already frustrated.
- Language is declared on the document element and updated when locale changes.
- A skip link precedes the form.

Automated checks catch a portion of this. Keyboard-only and screen-reader passes over
the full flow are part of the release evidence, because the parts that fail are usually
the parts automation does not see.

## Data Model

This theme holds no state. Its inputs are the Keycloak template model, the message
bundle for the negotiated locale, and the token-derived stylesheet.

### Message Bundle Discipline

```text
messages_en.properties      the reference
messages_id.properties      translated
```

Every locale carries the same keys with the same specificity. A translation that is
more specific than its English source is a disclosure defect: `invalidUserMessage`
rendered in one language as "Invalid credentials" and in another as "That account does
not exist" leaks account existence to anyone who switches language.

The bundle test asserts key parity, and enumeration-sensitive keys are asserted to
resolve to a uniform message in every locale.

**As built (1.1.0).** The kernel ships both bundles, Indonesian among its community translations,
so the theme's bundles carry only the keys it changes. It changes one: `accountDisabledMessage`.
The kernel's default, "Account is disabled, contact your administrator.", tells anyone who types an
identifier that it names an account, and that the account is disabled, which is what a suspended
Principal is. It reads as a failed sign-in in both locales, the wording the kernel already gives a
temporary or permanent lockout. `compat/theme_test.go` signs in with an unknown identifier, a wrong
password and a disabled account, in each locale, and requires the same status and message from all
three.

## API / Interface

The theme publishes no API. It consumes the Keycloak template contract, which is why
that contract is asserted by the upgrade suite in `TDD-identity-kernel-005`.

### Rendered Surfaces

```text
login                    identifier and credential, provider selection
login-otp                MFA challenge
webauthn-authenticate    passkey challenge
login-reset-password     recovery request
login-update-password    recovery completion and forced change
login-verify-email       identifier verification
login-oauth-grant        consent
error                    uniform error presentation
info                     uniform confirmation presentation
```

## Algorithms / Logic

### Enumeration Resistance

An unauthenticated visitor must not learn whether an identifier exists. Three surfaces
leak it, and all three are closed together, because closing one and leaving the others
is closing none.

**Message.** Failed authentication renders one message regardless of cause: unknown
identifier, wrong credential, and disabled account are indistinguishable. Recovery
renders the same confirmation whether or not the identifier resolved.

**Status and shape.** The same status code, the same page structure, and the same set of
rendered elements in every case. A missing element is as readable as a message.

**Timing.** An unknown identifier must not return faster than a wrong credential. The
kernel performs credential verification work in both paths; the theme's obligation is to
add no branch that shortens one, and the test measures both distributions rather than
inspecting the code.

For an unknown identifier, the kernel hashes a dummy password (`AuthenticatorUtils.dummyHash`).
Measured against 26.7.5, an unknown identifier, a wrong password and a disabled account all answer
in about 44 ms, and no pair is separable. Two paths answer an existing account about one hash
sooner. Both are STD-IAM-001 §3.1's recorded gaps:

| Path | Why it is shorter | Measured | Upstream |
| :-- | :-- | :-- | :-- |
| An empty password | `validatePassword` returns before hashing for an existing account | 16.4 ms against 42.1 ms | keycloak#51887, open |
| An account under lockout | The lockout is checked before the password | 16.0 ms against 42.1 ms | Not yet reported |

The message is the same in both, so only the time tells. No realm setting changes either path.

Recovery is the surface where this is most often lost, because a helpful confirmation
naming the address is exactly what a well-meaning designer writes.

### Locale Negotiation

```text
negotiate:
    explicit user selection, if present
    else Accept-Language against supported locales
    else the default locale

on render:
    set lang on the document element
    render from the negotiated bundle
    fall back per key to the reference bundle
```

A missing key falls back rather than rendering a raw key name. A raw key on the login
page is both a defect and a disclosure, because key names describe conditions.

### Browser Security

Every page the realm renders carries the realm's `browserSecurityHeaders`, which STD-IAM-001 §3.9
(2.4.0) fixes. Keycloak sends them on each HTML answer of the realm: the login page, the answer to a
failed sign-in, the second-factor and passkey pages, and its error pages.

```text
Content-Security-Policy      default-src 'self'; script-src 'self' 'unsafe-inline';
                             style-src 'self' 'unsafe-inline'; img-src 'self' data:;
                             frame-src 'self'; frame-ancestors 'none'; object-src 'none';
                             base-uri 'none'
Strict-Transport-Security    max-age=31536000; includeSubDomains
X-Frame-Options              DENY
X-Content-Type-Options       nosniff
Referrer-Policy              no-referrer
X-Robots-Tag                 none
```

**No page can be framed.** `frame-ancestors 'none'` and `X-Frame-Options: DENY` together close
clickjacking on the one page where a click grants a session. Keycloak's default allows its own
origin; this realm allows none. The OpenID Connect session-status iframe and sign-in inside an
iframe are therefore unavailable, and no client uses them: a browser application signs in through
its BFF.

**Nothing is loaded from another origin.** No analytics, no font CDN, no tag manager. `img-src`
also allows `data:` because the one-time-code enrolment page renders its QR code as one.

**Inline script is allowed: a recorded gap.** 1.1.0 asked for `script-src 'self'` with no inline
script. The stock `keycloak.v2` templates cannot meet it. Each of the following carries inline
script or inline handlers:

- `template.ftl`, which every page uses: an import map, module scripts, and an `onclick`;
- `login.ftl`: an `onsubmit`;
- `login-otp.ftl`: an inline script and `onclick`;
- `webauthn-authenticate.ftl`: an inline module script holding the request's `challenge`.

Of the 33 templates in 26.7.5, ten carry inline script and eleven inline handlers, sixteen in all.
Because the challenge changes with every request, no hash can name the passkey script. Meeting 1.1.0
would mean copying those sixteen templates, `template.ftl` among them. That contradicts §Override Surface, and every copy would
stop receiving the kernel's fixes. The gap closes when the kernel ships template nonces (Keycloak
pull request #49879, open). That upgrade then replaces `'unsafe-inline'` with a nonce and
`'strict-dynamic'`. Until then, the policy still refuses every script from another origin.

**No `form-action`.** Chrome applies it to the redirect that follows a form submission, so
`form-action 'self'` would block the return to the client after sign-in.

`Referrer-Policy: no-referrer` prevents identifiers or state parameters in the URL from
travelling to whatever the user visits next. HSTS takes effect behind the production load balancer's
TLS; a browser ignores it over the development server's plain HTTP.

`internal/realmdef` refuses a definition that weakens any of this before anything is applied, the
same way it refuses event retention below the floor.

## Configuration

| Setting | Value | Reason |
| :-- | :-- | :-- |
| Theme | `scnehaux` | Applied to login. The account console is not used: what follows sign-in is the Identity Experience's (ADR-IAM-001 §5.7). There is no email theme: the kernel sends no mail, and account security notifications are the Identity Control API's to decide and the Notification Platform's to deliver (ADR-IAM-007 §5.4). `realmdef` refuses an SMTP server and the `email` event listener, and `compat/no_mail_test.go` asserts the live realm has neither |
| Supported locales | `en`, `id` | Key parity asserted across both |
| Default locale | `en` | Reference bundle |
| Internationalization | enabled | Required for locale negotiation |
| Third-party origins | none | The page ships everything it loads |

Static assets are served from the same origin and are fingerprinted, so a theme change
invalidates caches without a version query string.

## Testing Strategy

**As built (1.5.0):** the theme in both locales, the language attribute, and the enumeration
message and status (`compat/theme_test.go`); the browser security headers on the login page, a
failed sign-in and an error page, and the absence of any other origin on the login page
(`compat/browser_headers_test.go`); the definition's refusal of a weaker header set
(`internal/realmdef`).

In a real browser (`browser/`, the `compat` workflow's `browser` job), Playwright drives Chromium
through one person's sign-ins in each locale (STD-GLB-FE-008 names Playwright for browser tests):

- the password, typed from the keyboard after a refused one;
- a one-time code enrolled, recovery codes acknowledged, then a code typed from the keyboard;
- a recovery code in place of the code, reached through "Try another way" and the authenticator
  selection page, each by Tab and Enter;
- a passkey bound, then used, through Chromium's virtual authenticator, the way Keycloak's own
  WebAuthn tests answer those pages.

Every surface the sequence reaches is scanned by axe-core against the WCAG 2.2 A and AA rules, in
the light and the dark scheme. STD-GLB-FE-009 names axe-core for automated scans. The surfaces are
the login page, the failed sign-in, the one-time-code enrolment, the recovery codes, the one-time
code, the authenticator selection, the recovery-code sign-in, the passkey binding, the passkey
sign-in and an error page. Since 1.7.0 they also include an account under lockout, the logout
confirmation and the page after it. The one-time-code enrolment, the recovery codes and the passkey
binding are this realm's three required actions. Each scan is a row in the job summary. Each row also
names what axe-core could not decide, with a node count, as needing review: that is left to the manual
audit, never counted as passed. Each scan is photographed in both schemes. The pictures are the
browser job's `login-pages-screenshots` artifact, the record of §Visual Language. No page may raise a
Content Security Policy violation; that is the proof that the realm's policy allows what the stock
templates and the theme's stylesheet run.

On every scanned page the header must read `Scnehaux`, the realm's display name, as rendered.

The account under lockout is a second person, refused ten times (the realm's `failureFactor`). The
right password must then read exactly as the wrong one did (§Enumeration Resistance).

The realm's flow has no identity-first or organization-selection page to scan. Its organization step
runs only on a session, and the client names the Tenant in its scope, so the kernel answers it without
a page (`compat/session_tenant_test.go`). The stylesheet still styles keycloak.v2's
`login-username.ftl` and the base `select-organization.ftl` by the classes they share.

`internal/themecontrast`, in the `contract` job's unit tests, holds the colour pairs to WCAG 2.2 AA in
both schemes after alpha composition (§Visual Language).

The timing comparison is `compat/timing_test.go`, and it follows dudect's method:

- the classes are measured interleaved in a random order;
- each pair is compared with Welch's t-test on every measurement and on the fastest 90 percent;
- an |t| above 10 is a separable difference.

An unknown identifier, a wrong password and a disabled account must not be separable. The two
recorded gaps are measured alongside them and written to the job summary.

**Not yet:** the screen-reader pass, which is manual release evidence.

### Accessibility

- Automated conformance across every rendered surface, in both themes and both locales.
- Keyboard-only completion of sign-in, MFA, recovery, and consent.
- Screen-reader pass over the same flows, recorded as release evidence.
- Every input has an associated label; every error is associated with its field.
- Contrast meets AA against the token palette in both themes.

### Enumeration

- An unknown identifier and a wrong credential produce identical message, status, and
  page structure.
- A disabled account is indistinguishable from both.
- Recovery renders the same confirmation for a resolving and a non-resolving identifier.
- Response time distributions for unknown, wrong-credential and disabled paths are
  compared, and a separable difference fails the test; the empty-password and lockout
  paths are measured and recorded.

### Localization

- Every locale carries every key of the reference bundle.
- No translated message is more specific than its reference.
- A missing key falls back to the reference rather than rendering the key name.
- `lang` on the document element matches the negotiated locale.

### Browser Security

- Every page the realm renders carries the declared header set.
- The Content-Security-Policy names no other origin, no `unsafe-eval`, and no `form-action`;
  `'unsafe-inline'` is the recorded gap until template nonces.
- No page loads a third-party origin.
- The login page cannot be framed.
- In a real browser, sign-in, the one-time code and the passkey pages raise no CSP violation.

### Upgrade

- Every overridden template is listed in this design with its reason.
- A candidate Keycloak release changing an overridden template's model fails the
  upgrade suite in `TDD-identity-kernel-005`.
- Removing an override and reverting to the stock template is attempted at each major
  upgrade, and the result is recorded.

## Security Notes

The login page is the estate's largest unauthenticated attack surface and its most
consequential accessibility surface at the same time. Both properties come from the same
fact: everyone reaches it, including people you did not choose.

Enumeration resistance is treated as three simultaneous properties because it is a
conjunction. A uniform message with a distinguishable timing signal is not resistance,
and the test suite measures timing rather than reading the templates.

The theme ships everything it loads. A font CDN on the login page is a third party that
can execute in the origin where credentials are typed, and no styling benefit justifies
that.

Every overridden template is a security surface as well as an upgrade liability. A stock
template that changes to add a protection will not reach a page that overrides it. That is
why each override carries a stated reason, and why `cmd/theme-overrides` fails on any release
that changes the stock template the copy was made from.

## Performance Notes

The theme is static assets and server-side templates. Assets are fingerprinted and
cached; templates render inside Keycloak with no external call.

The deliberate absence of third-party origins removes the DNS, TLS, and connection cost
those origins would add to the first page an unauthenticated visitor loads.

## Operational Notes

| Signal | Warning | Critical |
| :-- | :-- | :-- |
| Accessibility regression in CI | — | any occurrence |
| Message key missing in a supported locale | any occurrence | — |
| Timing separation between unknown and wrong-credential paths | — | statistically separable |
| Overridden template count | above five | — |
| Third-party origin requested by a rendered page | — | any occurrence |

The override count is a warning rather than a limit. It is a debt signal: each addition
raises the cost of every future upgrade, and seeing the number move is what prompts the
question of whether the change belonged in CSS.

Runbooks required before production: accessibility regression triage and theme
incompatibility during an upgrade.

## Traceability

| Relationship | Target |
| :-- | :-- |
| Parent system | SAD-001 — Scnehaux Identity Runtime |
| Realizes | SAD-002 — hosted login portion of the Identity Experience |
| Governed by | ADR-IAM-001 §5.7 — themes and supported UI extension points |
| Conforms to | PAD-PLT-001 §6.6 — WCAG 2.2 AA, safe recovery, no unnecessary account enumeration |
| Conforms to | STD-IAM-001 §3.9 (2.4.0) — browser security controls, the login pages' header set |
| Conforms to | STD-GLB-FE-003 — security headers |
| Conforms to | STD-GLB-FE-009 — accessibility and internationalization |
| Related design | `TDD-identity-kernel-005` — the upgrade suite that re-verifies every override |
| Related design | `TDD-identity-experience-001` — the authenticated surfaces reached after this one |
| Related design | identity-experience `packages/ui` — the tokens and styles §Visual Language copies |
| Conforms to | STD-GLB-FE-005 §3.9 — focus indicators drawn with `outline` |
