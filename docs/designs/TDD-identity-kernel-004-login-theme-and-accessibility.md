---
doc_meta:
  id: TDD-identity-kernel-004
  title: Hosted Login Theme, Accessibility, and Disclosure Discipline
  owner: Identity Platform Team
  version: 1.4.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-11
  last_reviewed: 2026-10-06
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
- Design tokens and component semantics, owned by the UI Platform.
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

**As built (1.3.0): two templates are overridden, because a test showed the stock ones fail.** The
theme `scnehaux` names `keycloak.v2` as its parent, as ADR-IAM-001 §5.7 decides. Keycloak documents
the mechanism: "When extending a theme you can override individual resources (templates,
stylesheets, etc.)" (ADR-IAM-001 [R33]).

| Copied template | Its reason | Upstream | Removed when |
| :-- | :-- | :-- | :-- |
| `template.ftl` | The `username` macro labels the read-only field that shows who is signing in with `for="username"`. The field's id is `kc-attempted-username`, so on every page after the first (the one-time code, the passkey) the field has no accessible name (WCAG 2.2 1.3.1, 4.1.2). axe-core reports it as `label`, critical, in `browser/`. The copy renames the group to the field's id and changes nothing else | Not yet reported | The pinned release labels the field |
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
| Theme | `scnehaux` | Applied to login. The account console is not used: what follows sign-in is the Identity Experience's (ADR-IAM-001 §5.7). The email theme follows the notification decision |
| Supported locales | `en`, `id` | Key parity asserted across both |
| Default locale | `en` | Reference bundle |
| Internationalization | enabled | Required for locale negotiation |
| Third-party origins | none | The page ships everything it loads |

Static assets are served from the same origin and are fingerprinted, so a theme change
invalidates caches without a version query string.

## Testing Strategy

**As built (1.4.0):** the theme in both locales, the language attribute, and the enumeration
message and status (`compat/theme_test.go`); the browser security headers on the login page, a
failed sign-in and an error page, and the absence of any other origin on the login page
(`compat/browser_headers_test.go`); the definition's refusal of a weaker header set
(`internal/realmdef`).

In a real browser (`browser/`, the `compat` workflow's `browser` job), Playwright drives Chromium
through one person's sign-ins in each locale (STD-GLB-FE-008 names Playwright for browser tests):

- the password, typed from the keyboard after a refused one;
- a one-time code enrolled, recovery codes acknowledged, then a code typed from the keyboard;
- a passkey bound, then used, through Chromium's virtual authenticator, the way Keycloak's own
  WebAuthn tests answer those pages.

Every surface the sequence reaches is scanned by axe-core against the WCAG 2.2 A and AA rules, in
the light and the dark scheme. STD-GLB-FE-009 names axe-core for automated scans. The surfaces are
the login page, the failed sign-in, the one-time-code enrolment, the recovery codes, the one-time
code, the passkey binding, the passkey sign-in and an error page. Each scan is a row in the job
summary. No page may raise a Content Security Policy violation; that is the proof that the realm's
policy allows what the stock templates run.

The timing comparison is `compat/timing_test.go`, and it follows dudect's method:

- the classes are measured interleaved in a random order;
- each pair is compared with Welch's t-test on every measurement and on the fastest 90 percent;
- an |t| above 10 is a separable difference.

An unknown identifier, a wrong password and a disabled account must not be separable. The two
recorded gaps are measured alongside them and written to the job summary.

**Not yet:**

- the recovery-code sign-in page and the authenticator selection page;
- the screen-reader pass, which is manual release evidence.

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
