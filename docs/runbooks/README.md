# Identity Kernel runbooks

Version 1.0.0. Owner: Identity Platform Team. Last reviewed 2026-10-07.

The production gate (ROADMAP §Gates) requires four runbooks. Three are here. The key ceremony
runbook waits on key custody (TDD-identity-kernel-002), which is not built yet.

| Runbook | Answers |
| :-- | :-- |
| [Console drift](console-drift.md) | `realm-apply` exits 2 and prints `DRIFT`, or refuses an unmanaged realm |
| [Failed upgrade](failed-upgrade.md) | a candidate Keycloak release fails `compat`, or a server does not come back after an upgrade |
| [Consumer reports an unknown `kid`](unknown-kid.md) | a protected resource rejects tokens with `verify: signing key is unknown` |
| Key ceremony | Not written. It waits on key custody (ROADMAP Week 2) |

## Why these exist

- TDD-identity-kernel-001, -002 and -005 each list the runbooks they require before production
  (§Operational Notes).
- NIST SP 800-61r3 asks organizations to "develop and maintain procedures for particularly
  important processes that may be urgently needed during emergency situations, such as redeploying
  the organization's primary authentication platform" [R1]. The kernel is that platform.
- Google SRE: "whenever an alert is created, a corresponding playbook entry is usually created" [R2].

## Where they apply today

No production kernel exists. `realm-apply` refuses every environment but `local`, `ci` and
`development`, because the signing key is generated in-process (`internal/realmdef/definition.go`,
`ParseEnvironment`). So each runbook is written for the one long-lived server there is, the
development server in [`deploy/dev/`](../../deploy/dev/README.md), and names what changes for
production under "Gaps".

## Conventions

- Every command, flag, exit status, log line and route named here exists in this repository or in
  the pinned Keycloak. A runbook that names something the code does not do is a defect. Fix the
  runbook in the same change as the code.
- Commands run in `deploy/dev` on the server, as the development server README runs them. The
  `realm-apply` service account's key never leaves the server, so a laptop cannot run them.
- Keep an incident record: what you saw, each command and its output, and what you decided.
- After each use, update the runbook with what was missing. "Details in playbooks go out of date at
  the same rate as production environment changes" [R2].
- A user-visible outage, a rollback or a restore gets a blameless postmortem. Google SRE lists
  "Data loss of any kind" and "On-call engineer intervention (release rollback, rerouting of
  traffic, etc.)" among its triggers [R3].

## References

| # | Source |
| :-- | :-- |
| R1 | NIST SP 800-61r3, *Incident Response Recommendations and Considerations for Cybersecurity Risk Management*, §2.3, <https://doi.org/10.6028/NIST.SP.800-61r3>, accessed 2026-10-07: "Organizations should also develop and maintain procedures for particularly important processes that may be urgently needed during emergency situations, such as redeploying the organization's primary authentication platform." |
| R2 | Google, *Site Reliability Workbook*, "On-Call", <https://sre.google/workbook/on-call/>, accessed 2026-10-07: "In SRE, whenever an alert is created, a corresponding playbook entry is usually created." and "Details in playbooks go out of date at the same rate as production environment changes." |
| R3 | Google, *Site Reliability Engineering*, "Postmortem Culture: Learning from Failure", <https://sre.google/sre-book/postmortem-culture/>, accessed 2026-10-07: "Blameless postmortems are a tenet of SRE culture"; triggers include "Data loss of any kind" and "On-call engineer intervention (release rollback, rerouting of traffic, etc.)". |
