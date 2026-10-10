import "dotenv/config";
import { PrismaClient } from "@prisma/client";
const db = new PrismaClient();
try {
  for (const settings of await db.organizationSettings.findMany()) {
    const cutoff = new Date(Date.now() - settings.retentionDays * 86400000);
    // Preserve events attached to an incident, including resolved cases. Evidence retention needs an explicit archive policy.
    const result = await db.securityEvent.deleteMany({
      where: {
        orgId: settings.orgId,
        timestamp: { lt: cutoff },
        incidentLinks: { none: {} },
      },
    });
    const heartbeat = await db.agentHeartbeat.deleteMany({
      where: { device: { orgId: settings.orgId }, createdAt: { lt: cutoff } },
    });
    await db.auditLog.create({
      data: {
        orgId: settings.orgId,
        actorId: "retention-job",
        action: "retention.run",
        details: {
          removedEvents: result.count,
          removedHeartbeats: heartbeat.count,
          cutoff: cutoff.toISOString(),
        },
      },
    });
    console.log(
      "Retention applied for organization " +
        settings.orgId +
        ": " +
        result.count +
        " unlinked events removed.",
    );
  }
  await db.session.deleteMany({ where: { expiresAt: { lt: new Date() } } });
  await db.deviceEnrollmentToken.deleteMany({
    where: { expiresAt: { lt: new Date(Date.now() - 86400000) } },
  });
} finally {
  await db.$disconnect();
}
