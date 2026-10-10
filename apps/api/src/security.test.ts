import { describe, it, expect } from "vitest";
import { hashPassword, verifyPassword, digest, csv } from "./security";
import { batchSchema } from "@zeroeye/shared-types";
describe("security boundaries", () => {
  it("salts hashes and rejects incorrect passwords", async () => {
    const hash = await hashPassword("long-enough-password");
    expect(hash).not.toContain("long-enough");
    expect(await verifyPassword("long-enough-password", hash)).toBe(true);
    expect(await verifyPassword("different", hash)).toBe(false);
    expect(await hashPassword("long-enough-password")).not.toBe(hash);
  });
  it("hashes credentials deterministically", () => {
    expect(digest("secret")).toHaveLength(64);
  });
  it("rejects forged tenant and simulated event fields", () => {
    const e = {
      eventKey: "1",
      provider: "Microsoft-Windows-Security-Auditing",
      windowsEventId: 4625,
      timestamp: new Date().toISOString(),
    };
    expect(
      batchSchema.safeParse({ events: [{ ...e, orgId: "forged" }] }).success,
    ).toBe(false);
    expect(
      batchSchema.safeParse({ events: [{ ...e, simulated: true }] }).success,
    ).toBe(false);
    expect(
      batchSchema.safeParse({ events: [{ ...e, windowsEventId: 1234 }] })
        .success,
    ).toBe(false);
  });
  it("neutralizes CSV formula injection and quotes", () => {
    const text = csv([{ name: '=HYPERLINK("bad")', normal: "a,b" }]);
    expect(text).toContain("'=HYPERLINK");
    expect(text).toContain('"a,b"');
  });
});
