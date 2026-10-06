// The hosted login pages in a real browser (TDD-identity-kernel-004 §Testing Strategy).
//
// In each locale, one person signs in the way a person does: the password typed from the keyboard,
// a one-time code enrolled and then typed, recovery codes acknowledged, a passkey registered and
// then used, through Chromium's virtual authenticator, as Keycloak's own WebAuthn tests do. Every
// surface the sequence reaches is scanned by axe-core in both colour schemes, and no page may raise
// a Content Security Policy violation: the realm's policy allows what the stock templates run, and
// this is where that is proven (STD-IAM-001 §3.9).
import { expect, test, type Page } from "@playwright/test";

import { authorizationURL, callbackListener, Codes, Fixtures, recordViolations, scan, type Person } from "./kernel";

type Surface = "password" | "configure-totp" | "recovery-codes" | "otp" | "webauthn-register" | "webauthn";

// surface names the page by what it asks for, as compat/levels_test.go does.
async function surface(page: Page, redirect: string): Promise<Surface | "callback"> {
  if (page.url().startsWith(redirect)) return "callback";
  const present = async (selector: string) => (await page.locator(selector).count()) > 0;
  if (await present("#registerWebAuthn")) return "webauthn-register";
  if (await present("#authenticateWebAuthnButton")) return "webauthn";
  if (await present("#kcRecoveryCodesConfirmationCheck")) return "recovery-codes";
  if (await present("#totpSecret")) return "configure-totp";
  if (await present("input[name=otp]")) return "otp";
  if (await present("#password")) return "password";
  throw new Error(`an unexpected page at ${page.url()}: ${await page.title()}`);
}

// tabTo moves the focus to the element with the keyboard alone, as a person who cannot use a
// pointer reaches it.
async function tabTo(page: Page, selector: string): Promise<void> {
  const target = page.locator(selector);
  for (let presses = 0; presses < 20; presses++) {
    if (await target.evaluate((element) => element === document.activeElement)) return;
    await page.keyboard.press("Tab");
  }
  throw new Error(`${selector} is not reachable by Tab`);
}

// submits runs an action that ends in a navigation, and waits for the page it loads.
async function submits(page: Page, action: () => Promise<void>): Promise<void> {
  const loaded = page.waitForEvent("load");
  await action();
  await loaded;
}

class Sequence {
  readonly seen: Surface[] = [];
  private scanned = new Set<Surface>();
  codes?: Codes;

  constructor(
    private page: Page,
    private locale: string,
    private clientId: string,
    private redirect: string,
    private person: Person,
  ) {}

  // signIn runs one authorization request to its code, answering each page the kernel shows, and
  // returns the pages it showed.
  async signIn(params: Record<string, string> = {}): Promise<Surface[]> {
    const shown: Surface[] = [];
    await this.page.goto(authorizationURL(this.clientId, this.redirect, { ui_locales: this.locale, ...params }));
    for (let step = 0; step < 8; step++) {
      const current = await surface(this.page, this.redirect);
      if (current === "callback") {
        expect(new URL(this.page.url()).searchParams.get("code"), "the redirect carries a code").toBeTruthy();
        return shown;
      }
      shown.push(current);
      this.seen.push(current);
      if (!this.scanned.has(current)) {
        this.scanned.add(current);
        await expect(this.page.locator("html")).toHaveAttribute("lang", this.locale);
        await scan(this.page, this.locale, current);
      }
      await this.answer(current);
    }
    throw new Error(`the sign-in did not reach a code; pages ${shown.join(",")}`);
  }

  private async answer(current: Surface): Promise<void> {
    const page = this.page;
    switch (current) {
      case "password":
        // On a re-authentication the kernel already knows the person and asks for the password alone.
        if (await page.locator("#username").isVisible()) {
          await tabTo(page, "#username");
          await page.keyboard.type(this.person.username);
        }
        await tabTo(page, "#password");
        await page.keyboard.type(this.person.password);
        return submits(page, () => page.keyboard.press("Enter"));
      case "configure-totp": {
        this.codes = new Codes(await page.locator("#totpSecret").inputValue());
        await page.locator("#totp").fill(await this.codes.next(page));
        await page.locator("#userLabel").fill("browser");
        return submits(page, () => page.locator("#saveTOTPBtn").click());
      }
      case "recovery-codes":
        await page.locator("#kcRecoveryCodesConfirmationCheck").check();
        return submits(page, () => page.locator("#saveRecoveryAuthnCodesBtn").click());
      case "otp": {
        if (!this.codes) throw new Error("the kernel asked for a code before one was enrolled");
        const code = await this.codes.next(page);
        await tabTo(page, "input[name=otp]");
        await page.keyboard.type(code);
        return submits(page, () => page.keyboard.press("Enter"));
      }
      case "webauthn-register":
        return submits(page, () => page.locator("#registerWebAuthn").click());
      case "webauthn":
        return submits(page, () => page.locator("#authenticateWebAuthnButton").click());
    }
  }
}

for (const locale of ["en", "id"]) {
  test(`the login pages in ${locale}: accessible, keyboard-operable, and within their policy`, async ({ page }) => {
    const fixtures = new Fixtures();
    const callback = await callbackListener();
    try {
      const violations = await recordViolations(page);
      // Chromium's virtual authenticator answers the WebAuthn pages; the label the registration asks
      // for in a prompt is accepted as offered.
      const cdp = await page.context().newCDPSession(page);
      await cdp.send("WebAuthn.enable");
      await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: {
          protocol: "ctap2",
          transport: "usb",
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      });
      page.on("dialog", (dialog) => void dialog.accept(dialog.defaultValue()));

      const clientId = await fixtures.client(callback.redirect);
      const person = await fixtures.person();
      const sequence = new Sequence(page, locale, clientId, callback.redirect, person);

      // A wrong password first: the answer is a page of its own, scanned before the right one.
      await page.goto(authorizationURL(clientId, callback.redirect, { ui_locales: locale }));
      await page.locator("#username").fill(person.username);
      await page.locator("#password").fill(`Wrong-${person.password}`);
      await submits(page, () => page.locator("#password").press("Enter"));
      await scan(page, locale, "failed sign-in");

      expect(await sequence.signIn(), "a password sign-in").toEqual(["password"]);

      const enrolment = await sequence.signIn({ acr_values: "aal2" });
      expect(enrolment.slice(-2), "aal2 with no second factor enrolls one").toEqual([
        "configure-totp",
        "recovery-codes",
      ]);

      await page.waitForTimeout(2_000); // max_age is measured in whole seconds
      const binding = await sequence.signIn({ acr_values: "aal2", max_age: "0", kc_action: "webauthn-register" });
      expect(binding, "a passkey is bound after an aal2 sign-in").toContain("otp");
      expect(binding.at(-1), "a passkey is bound after an aal2 sign-in").toBe("webauthn-register");

      // With the key alone, aal2 is the password and the key.
      await fixtures.removeCredentials(person, ["otp", "recovery-authn-codes"]);
      await page.waitForTimeout(2_000); // max_age is measured in whole seconds
      const passkey = await sequence.signIn({ acr_values: "aal2", max_age: "0" });
      expect(passkey, "aal2 with a passkey").toEqual(["password", "webauthn"]);

      // An error page: an authorization request from a client the realm does not hold.
      await page.goto(authorizationURL("browser-no-such-client", callback.redirect, { ui_locales: locale }));
      await scan(page, locale, "error page");

      expect(violations, "Content Security Policy violations").toEqual([]);
    } finally {
      await fixtures.remove();
      await callback.close();
    }
  });
}
