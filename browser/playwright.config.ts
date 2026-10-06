// The hosted login pages in a real browser (TDD-identity-kernel-004 §Testing Strategy), against the
// Keycloak the compat workflow starts. Chromium alone: it is the engine whose CSP and WebAuthn
// behaviour the realm's decisions were checked against (STD-IAM-001 §3.9), and it is the one that
// offers a virtual authenticator.
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "tests",
  // One sign-in sequence per locale, each waiting for a fresh one-time-code step at least once.
  timeout: 240_000,
  fullyParallel: true,
  workers: 2,
  forbidOnly: !!process.env.CI,
  // A flaky answer is an answer worth seeing, not one to retry away.
  retries: 0,
  reporter: [["list"]],
  use: {
    ...devices["Desktop Chrome"],
    trace: "retain-on-failure",
  },
});
