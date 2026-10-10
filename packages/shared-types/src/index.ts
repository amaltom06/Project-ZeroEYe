import { z } from "zod";
export const EVENT_IDS = [
  4624, 4625, 4634, 4648, 4672, 4688, 4720, 4726, 4740, 1102,
] as const;
export const roles = ["OWNER", "ADMIN", "ANALYST", "VIEWER"] as const;
export const statuses = [
  "NEW",
  "INVESTIGATING",
  "AWAITING_APPROVAL",
  "CONTAINED",
  "RESOLVED",
  "FALSE_POSITIVE",
] as const;
export const eventSchema = z
  .object({
    eventKey: z.string().min(1).max(160),
    provider: z.enum([
      "Microsoft-Windows-Security-Auditing",
      "Microsoft-Windows-Eventlog",
    ]),
    windowsEventId: z
      .number()
      .int()
      .refine(
        (id) => (EVENT_IDS as readonly number[]).includes(id),
        "Unsupported event ID",
      ),
    timestamp: z.string().datetime({ offset: true }),
    username: z.string().max(256).optional(),
    sourceIp: z.string().ip().optional(),
    processName: z.string().max(512).optional(),
    metadata: z
      .object({
        logonType: z.string().max(8).optional(),
        commandLine: z.string().max(2048).optional(),
        recordId: z.string().max(30).optional(),
        channel: z.literal("Security").optional(),
        status: z.string().max(40).optional(),
      })
      .strict()
      .default({}),
  })
  .strict()
  .refine(
    (e) =>
      e.provider !== "Microsoft-Windows-Eventlog" || e.windowsEventId === 1102,
    "Eventlog provider is only supported for event 1102",
  );
export const batchSchema = z
  .object({ events: z.array(eventSchema).min(1).max(200) })
  .strict();
export type IncomingEvent = z.infer<typeof eventSchema>;
export type EvidenceEvent = IncomingEvent & {
  id: string;
  deviceId: string;
  simulated: boolean;
};
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type RulePolicy = {
  enabled?: boolean;
  threshold?: number;
  windowSeconds?: number;
  suppressionSeconds?: number;
  allowedHours?: number[];
  trustedUsers?: string[];
};
export type Detection = {
  ruleId: string;
  name: string;
  description: string;
  severity: Severity;
  certainty: "RULE_MATCH";
  eventIds: string[];
  explanation: string;
  techniques: string[];
  group: string;
};
export function category(id: number) {
  return id === 4688
    ? "process"
    : id === 1102
      ? "audit"
      : id >= 4720
        ? "account"
        : "authentication";
}
export function outcome(id: number) {
  return id === 4625 ? "failure" : id === 4624 ? "success" : null;
}
