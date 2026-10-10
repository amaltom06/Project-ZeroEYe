import { describe, it, expect } from "vitest";
import { evaluate } from "./index";
import type { EvidenceEvent } from "@zeroeye/shared-types";
const base = (
  n: number,
  id = 4625,
  extra: Partial<EvidenceEvent> = {},
): EvidenceEvent => ({
  id: "event-" + n,
  eventKey: "key-" + n,
  deviceId: "one",
  simulated: false,
  provider: "Microsoft-Windows-Security-Auditing",
  windowsEventId: id,
  timestamp: new Date(1700000000000 + n * 1000).toISOString(),
  username: "alice",
  sourceIp: "192.0.2.1",
  metadata: {},
  ...extra,
});
describe("deterministic evidence rules", () => {
  it("requires five failures and links their evidence", () => {
    const es = Array.from({ length: 5 }, (_, n) => base(n));
    expect(evaluate(es[3]!, es.slice(0, 4))).toHaveLength(0);
    expect(
      evaluate(es[4]!, es).find((a) => a.ruleId === "ZE-001")?.eventIds,
    ).toHaveLength(5);
  });
  it("separates source, account, device, time and demo boundaries", () => {
    const es = Array.from({ length: 5 }, (_, n) => base(n));
    for (const extra of [
      { sourceIp: "192.0.2.2" },
      { username: "bob" },
      { deviceId: "two" },
      { simulated: true },
      { timestamp: new Date(1700001000000).toISOString() },
    ])
      expect(
        evaluate(base(5, 4625, extra), es).some((a) => a.ruleId === "ZE-001"),
      ).toBe(false);
  });
  it("handles missing IP without aggregating different accounts", () => {
    const es = Array.from({ length: 5 }, (_, n) =>
      base(n, 4625, { sourceIp: undefined }),
    );
    expect(evaluate(es[4]!, es).some((a) => a.ruleId === "ZE-001")).toBe(true);
    expect(evaluate(es[4]!, es).some((a) => a.ruleId === "ZE-002")).toBe(false);
  });
  it("detects distinct account spraying only with a known source", () => {
    const es = Array.from({ length: 5 }, (_, n) =>
      base(n, 4625, { username: "user" + n }),
    );
    expect(evaluate(es[4]!, es).some((a) => a.ruleId === "ZE-002")).toBe(true);
  });
  it("correlates a success after failures", () => {
    const es = Array.from({ length: 5 }, (_, n) => base(n));
    expect(evaluate(base(6, 4624), es).some((a) => a.ruleId === "ZE-008")).toBe(
      true,
    );
  });
  it("detects lockout and audit clearing", () => {
    expect(evaluate(base(1, 4740), [])[0]?.ruleId).toBe("ZE-003");
    expect(evaluate(base(1, 1102), [])[0]?.severity).toBe("CRITICAL");
  });
  it("does not flag ordinary PowerShell or privileges without explicit policy", () => {
    expect(
      evaluate(
        base(1, 4688, {
          processName: "C:\\Windows\\powershell.exe",
          metadata: { commandLine: "powershell -File backup.ps1" },
        }),
        [],
      ),
    ).toHaveLength(0);
    expect(evaluate(base(1, 4672), [])).toHaveLength(0);
  });
  it("flags encoded PowerShell and respects policy switches", () => {
    const e = base(1, 4688, {
      processName: "C:\\Windows\\powershell.exe",
      metadata: { commandLine: "powershell -enc SQBFAFgAIAAoACcAJwApAA==" },
    });
    expect(evaluate(e, [])[0]?.ruleId).toBe("ZE-006");
    expect(evaluate(e, [], { "ZE-006": { enabled: false } })).toHaveLength(0);
  });
  it("uses explicit schedules and privileged account policy", () => {
    expect(
      evaluate(base(1, 4672), [], { "ZE-004": { trustedUsers: ["system"] } })[0]
        ?.ruleId,
    ).toBe("ZE-004");
    const e = base(1, 4624);
    const hour = new Date(e.timestamp).getUTCHours();
    expect(
      evaluate(e, [], { "ZE-007": { allowedHours: [hour] } }),
    ).toHaveLength(0);
    expect(
      evaluate(e, [], { "ZE-007": { allowedHours: [(hour + 1) % 24] } })[0]
        ?.ruleId,
    ).toBe("ZE-007");
  });
  it("does not use future evidence", () => {
    const es = Array.from({ length: 5 }, (_, n) => base(n + 10));
    expect(evaluate(base(1), es)).toHaveLength(0);
  });
});
