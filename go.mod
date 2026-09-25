// The identity kernel's Go tooling: the realm contract and compatibility suite that runs against a
// live, digest-pinned Keycloak. The kernel itself is Keycloak; nothing here runs in production.
//
// Standard library only, deliberately. A suite whose job is to detect what an upgrade changed should
// not itself change when an unrelated dependency does.
module github.com/anshacerbia2/identity-kernel

go 1.25.0
