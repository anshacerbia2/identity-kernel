// What the browser suite needs from the kernel: a client and a person made through the Admin API
// and removed afterwards, the realm's one-time-code arithmetic, and the two recorders the suite
// asserts with, axe-core over a page and the CSP violations a page raised.
import { createHash, createHmac, randomBytes } from "node:crypto";
import { appendFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

import { AxeBuilder } from "@axe-core/playwright";
import { expect, type Page } from "@playwright/test";

export const base = required("KEYCLOAK_URL").replace(/\/+$/, "");
export const realm = "scnehaux";

// The client's redirect: a listener of the test's own, on the runner's loopback, that answers every
// request with an empty page. The code in the URL the browser lands on is the proof that the sign-in
// completed. A route cannot stand in for it: Playwright does not route the request a redirect makes,
// and compat's http://127.0.0.1:9 is a port Chromium refuses to navigate to.
export async function callbackListener(): Promise<{ redirect: string; close(): Promise<void> }> {
  const server = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/html" }).end("<!doctype html><title>callback</title>");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    redirect: `http://127.0.0.1:${port}/callback`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

// The master realm's access token lives a minute, and a sequence waits longer than that for a
// fresh one-time-code step, so every call asks for its own.
async function adminToken(): Promise<string> {
  const response = await fetch(`${base}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "password",
      client_id: "admin-cli",
      username: required("KEYCLOAK_ADMIN_USER"),
      password: required("KEYCLOAK_ADMIN_PASSWORD"),
    }),
  });
  if (!response.ok) throw new Error(`the admin token was refused with ${response.status}`);
  return ((await response.json()) as { access_token: string }).access_token;
}

async function call(method: string, path: string, body?: unknown): Promise<Response> {
  const response = await fetch(`${base}/admin/realms/${realm}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${await adminToken()}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(`${method} ${path} answered ${response.status}: ${await response.text()}`);
  }
  return response;
}

function created(response: Response): string {
  const location = response.headers.get("location") ?? "";
  return location.slice(location.lastIndexOf("/") + 1);
}

function suffix(): string {
  return randomBytes(6).toString("hex");
}

// uuidV7 is the Principal identifier the realm's user profile requires, as compat/contract_test.go
// makes it.
function uuidV7(): string {
  const b = randomBytes(16);
  const ms = BigInt(Date.now());
  for (let i = 0; i < 6; i++) b[i] = Number((ms >> BigInt(40 - 8 * i)) & 0xffn);
  b[6] = (b[6] & 0x0f) | 0x70;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export interface Person {
  userID: string;
  username: string;
  password: string;
}

// The fixtures one test made, removed by remove() whatever the test's outcome.
export class Fixtures {
  private clients: string[] = [];
  private users: string[] = [];

  // A confidential client with the authorization code flow and PKCE, as compat's providerCaller.
  async client(redirect: string): Promise<string> {
    const clientId = `browser-${suffix()}`;
    const response = await call("POST", "/clients", {
      clientId,
      protocol: "openid-connect",
      publicClient: false,
      secret: `browser-${suffix()}`,
      standardFlowEnabled: true,
      directAccessGrantsEnabled: false,
      serviceAccountsEnabled: false,
      redirectUris: [redirect],
      attributes: { "pkce.code.challenge.method": "S256", "access.token.signed.response.alg": "PS256" },
    });
    this.clients.push(created(response));
    return clientId;
  }

  // A person with a password and no second factor, as compat's createPrincipal.
  async person(): Promise<Person> {
    const username = `browser-${suffix()}`;
    const password = `Browser-${suffix()}!`;
    const response = await call("POST", "/users", {
      username,
      enabled: true,
      email: `${username}@browser.invalid`,
      emailVerified: true,
      firstName: "Browser",
      lastName: "Principal",
      attributes: { scnehaux_principal_id: [uuidV7()], scnehaux_subject_type: ["human"] },
      credentials: [{ type: "password", value: password, temporary: false }],
      requiredActions: [],
    });
    const userID = created(response);
    this.users.push(userID);
    return { userID, username, password };
  }

  // Removes every credential of the given types, so a sign-in is answered by what remains.
  async removeCredentials(person: Person, types: string[]): Promise<void> {
    const response = await call("GET", `/users/${person.userID}/credentials`);
    for (const credential of (await response.json()) as { id: string; type: string }[]) {
      if (types.includes(credential.type)) {
        await call("DELETE", `/users/${person.userID}/credentials/${credential.id}`);
      }
    }
  }

  async remove(): Promise<void> {
    for (const id of this.users) await call("DELETE", `/users/${id}`);
    for (const id of this.clients) await call("DELETE", `/clients/${id}`);
  }
}

// The authorization request a client's browser makes. The code is never exchanged, so the verifier
// is not kept.
export function authorizationURL(clientId: string, redirect: string, params: Record<string, string>): string {
  const challenge = createHash("sha256").update(randomBytes(32).toString("base64url")).digest("base64url");
  const query = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    redirect_uri: redirect,
    scope: "openid",
    state: "browser",
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...params,
  });
  return `${base}/realms/${realm}/protocol/openid-connect/auth?${query}`;
}

// The realm's one-time-code policy: HmacSHA1, 30-second steps, six digits, keyed with the secret's
// bytes as the enrolment page holds them in totpSecret (compat/levels_test.go).
export class Codes {
  private lastStep = 0;

  constructor(readonly secret: string) {}

  // A code for a step no earlier code used: the kernel refuses a code used once.
  async next(page: Page): Promise<string> {
    let step = Math.floor(Date.now() / 30_000);
    if (step <= this.lastStep) {
      await page.waitForTimeout((this.lastStep + 1) * 30_000 - Date.now() + 1_000);
      step = Math.floor(Date.now() / 30_000);
    }
    this.lastStep = step;
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(step));
    const sum = createHmac("sha1", Buffer.from(this.secret)).update(counter).digest();
    const offset = sum[sum.length - 1] & 0x0f;
    return String((sum.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
  }
}

// recordViolations collects every CSP violation the page raises, from the event the browser fires
// and from the console line it writes, from before the page's first script runs.
export async function recordViolations(page: Page): Promise<string[]> {
  const violations: string[] = [];
  await page.exposeBinding("__reportViolation", (_source, violation: string) => {
    violations.push(violation);
  });
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (event) => {
      (window as unknown as { __reportViolation(v: string): void }).__reportViolation(
        `${event.effectiveDirective} refused ${event.blockedURI || "inline code"} on ${event.documentURI}`,
      );
    });
  });
  page.on("console", (message) => {
    if (message.type() === "error" && /Content Security Policy/i.test(message.text())) {
      violations.push(message.text());
    }
  });
  return violations;
}

// The WCAG 2.2 A and AA rules axe-core carries (PAD-PLT-001 §6.6, STD-GLB-FE-009).
const wcag = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

// scan runs axe-core over the page as it stands, in the light scheme and in the dark one: the
// theme follows prefers-color-scheme, so each is a rendering of its own.
export async function scan(page: Page, locale: string, surface: string): Promise<void> {
  for (const colorScheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme });
    await page.waitForFunction(
      (dark) => document.documentElement.classList.contains("pf-v5-theme-dark") === dark,
      colorScheme === "dark",
    );
    const results = await new AxeBuilder({ page }).withTags(wcag).analyze();
    const found = results.violations.map(
      (v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`,
    );
    summarize(`| ${surface} | ${locale} | ${colorScheme} | ${results.passes.length} | ${found.length} |`);
    expect.soft(found, `axe-core on ${surface}, ${locale}, ${colorScheme}`).toEqual([]);
  }
  await page.emulateMedia({ colorScheme: "light" });
}

// summarize adds a row to the job summary, when there is one.
function summarize(row: string): void {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (file) appendFileSync(file, `${row}\n`);
}
