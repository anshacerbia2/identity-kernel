// Package compat asserts the declared realm contract against a live Keycloak.
//
// TDD-identity-kernel-001 publishes three properties other repositories build against: the issuer
// form, the claim set per token surface, and the closed creation paths. Downstream domains persist
// against those, so they are asserted here rather than observed, and every Keycloak upgrade runs
// this suite before it is accepted.
//
// It is also where the proof-of-concept questions are answered. The answers are recorded against
// the exact image in image/keycloak.ref: an answer about "Keycloak 26" is an answer about a tag, and
// a tag can point at different bytes tomorrow.
//
// The suite needs a running Keycloak. With KEYCLOAK_URL unset it skips, and with REQUIRE_INTEGRATION
// set a skip becomes a failure -- otherwise a Keycloak that never came up in CI would leave every
// assertion unrun and the build green.
package compat
