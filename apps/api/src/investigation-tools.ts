import { z } from "zod";
import type { PrismaClient } from "@prisma/client";
import { RULES } from "@zeroeye/detection-rules";
// Construct only after session/membership validation. The tenant is captured, never accepted from a tool payload.
export function investigationTools(db: PrismaClient, organizationId: string) {
  const orgId = z.string().uuid().parse(organizationId);
  const key = z.object({ id: z.string().uuid() }).strict();
  return {
    SearchSecurityEvents: async (input: unknown) => {
      const v = z
        .object({
          deviceId: z.string().uuid().optional(),
          from: z.string().datetime({ offset: true }),
          limit: z.number().int().min(1).max(100).default(50),
        })
        .strict()
        .parse(input);
      return db.securityEvent.findMany({
        where: {
          orgId,
          ...(v.deviceId ? { deviceId: v.deviceId } : {}),
          timestamp: { gte: new Date(v.from) },
        },
        take: v.limit,
        orderBy: { timestamp: "desc" },
        select: {
          id: true,
          deviceId: true,
          windowsEventId: true,
          timestamp: true,
          outcome: true,
          simulated: true,
        },
      });
    },
    GetDeviceDetails: async (input: unknown) => {
      const { id } = key.parse(input);
      return db.device.findFirst({
        where: { id, orgId },
        select: {
          id: true,
          hostname: true,
          active: true,
          lastHeartbeat: true,
          lastEvent: true,
          healthError: true,
        },
      });
    },
    GetIncidentDetails: async (input: unknown) => {
      const { id } = key.parse(input);
      return db.incident.findFirst({
        where: { id, orgId },
        include: {
          events: { take: 100, include: { event: true } },
          alert: true,
        },
      });
    },
    GetRelatedAlerts: async (input: unknown) => {
      const { id } = key.parse(input);
      return db.detectionAlert.findMany({
        where: { orgId, deviceId: id },
        take: 50,
        orderBy: { detectedAt: "desc" },
        select: {
          id: true,
          ruleId: true,
          severity: true,
          eventIds: true,
          explanation: true,
        },
      });
    },
    GetAuthenticationTimeline: async (input: unknown) => {
      const v = z
        .object({
          deviceId: z.string().uuid(),
          from: z.string().datetime({ offset: true }),
          to: z.string().datetime({ offset: true }),
        })
        .strict()
        .parse(input);
      return db.securityEvent.findMany({
        where: {
          orgId,
          deviceId: v.deviceId,
          category: "authentication",
          timestamp: { gte: new Date(v.from), lte: new Date(v.to) },
        },
        orderBy: { timestamp: "asc" },
        take: 100,
        select: {
          id: true,
          windowsEventId: true,
          timestamp: true,
          outcome: true,
          simulated: true,
        },
      });
    },
    GetDetectionRule: async (input: unknown) => {
      const v = z
        .object({ ruleId: z.string().max(20) })
        .strict()
        .parse(input);
      const rule = RULES.find((r) => r.id === v.ruleId);
      return rule
        ? {
            ...rule,
            policy: (
              await db.detectionRule.findUnique({
                where: { orgId_ruleId: { orgId, ruleId: rule.id } },
              })
            )?.policy ?? { enabled: true },
          }
        : null;
    },
    GenerateInvestigationSummary: async (input: unknown) => {
      const { id } = key.parse(input);
      const incident = await db.incident.findFirst({
        where: { id, orgId },
        select: {
          id: true,
          title: true,
          severity: true,
          status: true,
          events: {
            take: 100,
            select: {
              event: {
                select: {
                  id: true,
                  windowsEventId: true,
                  timestamp: true,
                  outcome: true,
                  simulated: true,
                },
              },
            },
          },
        },
      });
      return incident
        ? {
            incidentId: incident.id,
            title: incident.title,
            severity: incident.severity,
            status: incident.status,
            evidence: incident.events.map((e) => e.event),
          }
        : null;
    },
  };
}
