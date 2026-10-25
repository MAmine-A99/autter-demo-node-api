import { createRequire } from "node:module";
import { describe, expect, test } from "vitest";
import { buildApp } from "./app.js";

const require = createRequire(import.meta.url);

describe("zod CVE remediation (GHSA-mrhx-c7xc-m3w5)", () => {
  test("zod is upgraded to a fixed 4.x release", () => {
    const zodPkg = require("zod/package.json");
    const [major, minor, patch] = zodPkg.version.split(".").map(Number);
    expect(major).toBe(4);
    expect(minor).toBeGreaterThanOrEqual(6);
    expect(patch).toBeGreaterThanOrEqual(6);
  });

  test("project validation still accepts valid nested config and rejects bad types", async () => {
    const app = buildApp();
    const ok = await app.inject({
      method: "POST",
      url: "/api/projects",
      payload: { name: "p", config: { retries: 3 } },
    });
    expect(ok.statusCode).toBe(200);
    expect(ok.json()).toEqual({ name: "p", config: { retries: 3 } });

    const bad = await app.inject({
      method: "POST",
      url: "/api/projects",
      payload: { name: "p", config: { retries: "not-a-number" } },
    });
    expect(bad.statusCode).toBe(500);
  });
});
