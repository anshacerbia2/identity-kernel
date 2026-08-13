---
doc_meta:
  id: TDD-identity-kernel-004
  title: Hosted Login Theme, Accessibility, and Disclosure Discipline
  owner: Identity Platform Team
  version: 1.0.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-11
  last_reviewed: 2026-08-11
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

```text
overridden templates
    login.ftl                 unified identifier field and provider ordering
    login-otp.ftl             MFA challenge copy and input semantics
    login-reset-password.ftl  enumeration-safe confirmation copy
    error.ftl                 uniform error presentation
    template.ftl              document shell, language attributes, skip link
```

Five. Anything not on that list is styled, not forked, and adding to the list is a
reviewed decision rather than a convenience.

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

Every unauthenticated page carries, per STD-GLB-FE-003 and STD-IAM-001 §3.9:

```text
Content-Security-Policy      default-src 'none'; script-src 'self'; style-src 'self';
                             img-src 'self' data:; form-action 'self'; frame-ancestors 'none'
Strict-Transport-Security    max-age=31536000; includeSubDomains
X-Frame-Options              DENY
X-Content-Type-Options       nosniff
Referrer-Policy              no-referrer
```

No inline script, no inline event handler, no third-party origin. The login page loads
nothing it does not ship, which means no analytics, no font CDN, and no tag manager.

`frame-ancestors 'none'` and `X-Frame-Options: DENY` together close clickjacking on the
one page where a click grants a session.

`Referrer-Policy: no-referrer` prevents identifiers or state parameters in the URL from
travelling to whatever the user visits next.

## Configuration

| Setting | Value | Reason |
| :-- | :-- | :-- |
| Theme | `scnehaux` | Applied to login, account, and email |
| Supported locales | `en`, `id` | Key parity asserted across both |
| Default locale | `en` | Reference bundle |
| Internationalization | enabled | Required for locale negotiation |
| Third-party origins | none | The page ships everything it loads |

Static assets are served from the same origin and are fingerprinted, so a theme change
invalidates caches without a version query string.

## Testing Strategy

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
- Response time distributions for unknown and wrong-credential paths are compared, and
  a separable difference fails the test.

### Localization

- Every locale carries every key of the reference bundle.
- No translated message is more specific than its reference.
- A missing key falls back to the reference rather than rendering the key name.
- `lang` on the document element matches the negotiated locale.

### Browser Security

- Every unauthenticated page carries the full header set.
- The Content-Security-Policy contains no `unsafe-inline` and no `unsafe-eval`.
- No page loads a third-party origin.
- The login page cannot be framed.

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

The five overridden templates are a security surface as well as an upgrade liability. A
stock template that changes to add a protection will not reach a page that overrides it,
which is why each override carries a stated reason and is re-tested for removal at every
major upgrade.

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
| Conforms to | STD-IAM-001 §3.9 — browser security controls |
| Conforms to | STD-GLB-FE-003 — security headers |
| Conforms to | STD-GLB-FE-009 — accessibility and internationalization |
| Related design | `TDD-identity-kernel-005` — the upgrade suite that re-verifies every override |
| Related design | `TDD-identity-experience-001` — the authenticated surfaces reached after this one |
