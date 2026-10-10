import type {
  Detection,
  EvidenceEvent,
  RulePolicy,
  Severity,
} from "@zeroeye/shared-types";
export const RULES = [
  {
    id: "ZE-001",
    name: "Repeated failed logons",
    severity: "HIGH",
    description:
      "Five failures for the same device, account and source in two minutes.",
    techniques: ["T1110.001"],
  },
  {
    id: "ZE-002",
    name: "Possible password spraying",
    severity: "HIGH",
    description:
      "Failures across five accounts from one known source in five minutes.",
    techniques: ["T1110.003"],
  },
  {
    id: "ZE-003",
    name: "Account locked out",
    severity: "MEDIUM",
    description: "Windows reported an account lockout.",
    techniques: [],
  },
  {
    id: "ZE-004",
    name: "Privileged logon outside policy",
    severity: "MEDIUM",
    description:
      "Privileged account is absent from an explicitly configured trusted-user list.",
    techniques: [],
  },
  {
    id: "ZE-005",
    name: "Security audit log cleared",
    severity: "CRITICAL",
    description: "Windows reported that its Security log was cleared.",
    techniques: ["T1070.001"],
  },
  {
    id: "ZE-006",
    name: "Encoded PowerShell execution",
    severity: "HIGH",
    description:
      "PowerShell was launched with an encoded-command argument; review intent.",
    techniques: ["T1059.001"],
  },
  {
    id: "ZE-007",
    name: "Logon outside configured hours",
    severity: "LOW",
    description:
      "A successful logon occurred outside explicitly configured UTC hours.",
    techniques: [],
  },
  {
    id: "ZE-008",
    name: "Success after repeated failures",
    severity: "HIGH",
    description:
      "A successful logon followed five failures for the same device, account and source.",
    techniques: ["T1110"],
  },
] as const;
export function evaluate(
  event: EvidenceEvent,
  history: EvidenceEvent[],
  policies: Record<string, RulePolicy> = {},
): Detection[] {
  const result: Detection[] = [];
  const now = Date.parse(event.timestamp);
  for (const rule of RULES) {
    const p = policies[rule.id] ?? {};
    if (p.enabled === false) continue;
    const window =
      (p.windowSeconds ?? (rule.id === "ZE-002" ? 300 : 120)) * 1000;
    const preceding = history.filter(
      (e) =>
        e.deviceId === event.deviceId &&
        e.simulated === event.simulated &&
        Date.parse(e.timestamp) <= now &&
        Date.parse(e.timestamp) >= now - window,
    );
    const identity = (e: EvidenceEvent) => e.username?.toLowerCase() ?? null;
    const same = preceding.filter(
      (e) =>
        e.windowsEventId === 4625 &&
        identity(e) === identity(event) &&
        (e.sourceIp ?? null) === (event.sourceIp ?? null),
    );
    let evidence: EvidenceEvent[] = [];
    let explanation = "";
    let group = event.username?.toLowerCase() ?? "unknown-account";
    if (
      rule.id === "ZE-001" &&
      event.windowsEventId === 4625 &&
      same.length >= (p.threshold ?? 5)
    ) {
      evidence = same;
      explanation =
        same.length +
        " failures in " +
        window / 1000 +
        " seconds. Source " +
        (event.sourceIp ?? "unavailable; local account grouping used") +
        ".";
    }
    if (
      rule.id === "ZE-002" &&
      event.windowsEventId === 4625 &&
      event.sourceIp
    ) {
      const failures = preceding.filter(
        (e) =>
          e.windowsEventId === 4625 &&
          e.sourceIp === event.sourceIp &&
          e.username,
      );
      const count = new Set(failures.map(identity)).size;
      if (count >= (p.threshold ?? 5)) {
        evidence = failures;
        group = event.sourceIp;
        explanation =
          count + " distinct accounts failed from " + event.sourceIp + ".";
      }
    }
    if (rule.id === "ZE-003" && event.windowsEventId === 4740) {
      evidence = [event];
      explanation =
        "Windows event 4740 reports an account lockout; this does not establish malicious intent.";
    }
    if (
      rule.id === "ZE-004" &&
      event.windowsEventId === 4672 &&
      p.trustedUsers?.length &&
      event.username &&
      !p.trustedUsers.some((u) => u.toLowerCase() === identity(event))
    ) {
      evidence = [event];
      explanation =
        "Privileged logon account is not on the configured trusted-user list.";
    }
    if (rule.id === "ZE-005" && event.windowsEventId === 1102) {
      evidence = [event];
      explanation =
        "Windows event 1102 reports Security audit log clearing. Validate whether maintenance was authorized.";
    }
    if (
      rule.id === "ZE-006" &&
      event.windowsEventId === 4688 &&
      /(?:^|[\\/])(?:powershell|pwsh)(?:\.exe)?$/i.test(
        event.processName ?? "",
      ) &&
      /(?:^|\s)-(?:enc|encodedcommand|e)\s+['"]?[A-Za-z0-9+/]{16,}={0,2}(?:['"]?\s|$)/i.test(
        event.metadata.commandLine ?? "",
      )
    ) {
      evidence = [event];
      explanation =
        "Encoded-command argument matched. Legitimate automation can use this flag; review the parent process and owner.";
    }
    if (
      rule.id === "ZE-007" &&
      event.windowsEventId === 4624 &&
      p.allowedHours?.length &&
      !p.allowedHours.includes(new Date(now).getUTCHours())
    ) {
      evidence = [event];
      explanation =
        "Successful logon falls outside the configured UTC schedule.";
    }
    if (
      rule.id === "ZE-008" &&
      event.windowsEventId === 4624 &&
      same.length >= (p.threshold ?? 5)
    ) {
      evidence = [...same, event];
      explanation =
        "Successful logon followed " +
        same.length +
        " failures; verify the account owner and source.";
    }
    if (evidence.length)
      result.push({
        ruleId: rule.id,
        name: rule.name,
        description: rule.description,
        severity: rule.severity as Severity,
        certainty: "RULE_MATCH",
        eventIds: [...new Set(evidence.map((e) => e.id))].slice(-200),
        explanation,
        techniques: [...rule.techniques],
        group: group + "|" + (event.sourceIp ?? "unknown-source"),
      });
  }
  return result;
}
