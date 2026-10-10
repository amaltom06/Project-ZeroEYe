import { randomUUID } from "node:crypto";
import { log } from "./logger.js";
import express, { type Request, type Response } from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { rateLimit } from "express-rate-limit";
import { z, ZodError } from "zod";
import { Prisma, type PrismaClient } from "@prisma/client";
import {
  batchSchema,
  category,
  outcome,
  roles,
  statuses,
  EVENT_IDS,
  type EvidenceEvent,
  type RulePolicy,
} from "@zeroeye/shared-types";
import { RULES, evaluate } from "@zeroeye/detection-rules";
import {
  token,
  digest,
  hashPassword,
  verifyPassword,
  csv,
} from "./security.js";
import { config } from "./config.js";
import { investigationTools } from "./investigation-tools.js";
class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
const id = (r: Request, key = "id") => z.string().uuid().parse(r.params[key]);
const pageSchema = z.object({
  page: z.coerce.number().int().min(1).max(10000).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});
type Context = {
  userId: string;
  orgId: string;
  role: string;
  csrf: string;
  sessionId: string;
};
const context = (r: Response) => r.locals.ctx as Context;
const requireRole = (r: Response, allowed: string[]) => {
  if (!allowed.includes(context(r).role))
    throw new HttpError(403, "Insufficient role");
};
const analyst = (r: Response) => requireRole(r, ["OWNER", "ADMIN", "ANALYST"]);
const admin = (r: Response) => requireRole(r, ["OWNER", "ADMIN"]);
const policySchema = z
  .object({
    enabled: z.boolean().optional(),
    threshold: z.number().int().min(2).max(100).optional(),
    windowSeconds: z.number().int().min(30).max(600).optional(),
    suppressionSeconds: z.number().int().min(0).max(3600).optional(),
    allowedHours: z.array(z.number().int().min(0).max(23)).max(24).optional(),
    trustedUsers: z.array(z.string().max(256)).max(100).optional(),
  })
  .strict();
export function createApp(db: PrismaClient) {
  const app = express();
  let publish = (_org: string, _type: string) => {};
  app.disable("x-powered-by");
  app.use((req, res, next) => {
    const requestId = randomUUID();
    const start = performance.now();
    res.setHeader("X-Request-ID", requestId);
    res.on("finish", () =>
      log.info(
        {
          requestId,
          method: req.method,
          route: req.route?.path,
          status: res.statusCode,
          durationMs: Math.round(performance.now() - start),
        },
        "request completed",
      ),
    );
    next();
  });
  app.use(helmet());
  app.use(express.json({ limit: "512kb" }));
  app.use(cookieParser());
  app.use((req, res, next) => {
    if (req.headers.origin && req.headers.origin !== config.WEB_ORIGIN)
      return res.status(403).json({ error: "Origin not permitted" });
    next();
  });
  app.get("/api/health", async (_req, res) => {
    await db.$queryRaw`SELECT 1`;
    res.json({ status: "ok", version: "0.1.0" });
  });
  const audit = (
    tx: Prisma.TransactionClient,
    c: { orgId: string; userId?: string },
    action: string,
    targetId?: string,
    details: Prisma.InputJsonValue = {},
  ) =>
    tx.auditLog.create({
      data: {
        orgId: c.orgId,
        actorId: c.userId ?? "agent",
        action,
        targetId,
        details,
      },
    });
  async function issueSession(res: Response, userId: string) {
    const raw = token();
    const csrf = token();
    await db.session.create({
      data: {
        id: digest(raw),
        userId,
        csrf,
        expiresAt: new Date(Date.now() + config.SESSION_HOURS * 3600000),
      },
    });
    res.cookie("zeroeye_session", raw, {
      httpOnly: true,
      secure: config.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      maxAge: config.SESSION_HOURS * 3600000,
    });
    return csrf;
  }
  const authLimiter = rateLimit({
    windowMs: 900000,
    limit: 30,
    standardHeaders: "draft-8",
    legacyHeaders: false,
  });
  app.use("/api/auth/register", authLimiter);
  app.use("/api/auth/login", authLimiter);
  app.post("/api/auth/register", async (req, res) => {
    if (req.headers.origin !== config.WEB_ORIGIN)
      throw new HttpError(403, "Origin required");
    const v = z
      .object({
        email: z
          .string()
          .email()
          .max(254)
          .transform((s) => s.toLowerCase()),
        name: z.string().trim().min(1).max(100),
        password: z.string().min(12).max(128),
        organization: z.string().trim().min(1).max(100),
        demo: z.boolean().default(false),
      })
      .strict()
      .parse(req.body);
    const passwordHash = await hashPassword(v.password);
    const user = await db.$transaction(async (tx) => {
      const u = await tx.user.create({
        data: { email: v.email, name: v.name, passwordHash },
      });
      const org = await tx.organization.create({
        data: {
          name: v.organization,
          demo: v.demo,
          members: { create: { userId: u.id, role: "OWNER" } },
          settings: { create: {} },
        },
      });
      await audit(tx, { orgId: org.id, userId: u.id }, "user.register", u.id);
      return u;
    });
    const csrf = await issueSession(res, user.id);
    res
      .status(201)
      .json({
        user: { id: user.id, name: user.name, email: user.email },
        csrf,
      });
  });
  app.post("/api/auth/login", async (req, res) => {
    if (req.headers.origin !== config.WEB_ORIGIN)
      throw new HttpError(403, "Origin required");
    const v = z
      .object({
        email: z
          .string()
          .email()
          .max(254)
          .transform((s) => s.toLowerCase()),
        password: z.string().min(1).max(128),
      })
      .strict()
      .parse(req.body);
    const user = await db.user.findUnique({ where: { email: v.email } });
    const valid = await verifyPassword(
      v.password,
      user?.passwordHash ??
        "00000000000000000000000000000000:" + "00".repeat(64),
    );
    if (!user || !valid) throw new HttpError(401, "Invalid email or password");
    const csrf = await issueSession(res, user.id);
    for (const m of await db.organizationMember.findMany({
      where: { userId: user.id },
    }))
      await audit(db, m, "user.login", user.id);
    res.json({
      user: { id: user.id, email: user.email, name: user.name },
      csrf,
    });
  });
  // Agent authentication is intentionally independent of user session authentication.
  const agent = express.Router();
  agent.use(
    rateLimit({
      windowMs: 60000,
      limit: 240,
      standardHeaders: "draft-8",
      legacyHeaders: false,
    }),
  );
  agent.post("/enroll", async (req, res) => {
    const v = z
      .object({
        enrollmentToken: z.string().min(32).max(64),
        hostname: z.string().trim().min(1).max(253),
        osVersion: z.string().max(128),
        agentVersion: z.literal("0.1.0"),
      })
      .strict()
      .parse(req.body);
    const raw = token();
    const device = await db.$transaction(async (tx) => {
      const enrollment = await tx.deviceEnrollmentToken.findUnique({
        where: { tokenHash: digest(v.enrollmentToken) },
        include: { organization: true },
      });
      if (!enrollment)
        throw new HttpError(401, "Enrollment token invalid or expired");
      const used = await tx.deviceEnrollmentToken.updateMany({
        where: {
          id: enrollment.id,
          usedAt: null,
          expiresAt: { gt: new Date() },
        },
        data: { usedAt: new Date() },
      });
      if (!used.count)
        throw new HttpError(401, "Enrollment token invalid or expired");
      const d = await tx.device.create({
        data: {
          orgId: enrollment.orgId,
          hostname: v.hostname,
          osVersion: v.osVersion,
          agentVersion: v.agentVersion,
          simulated: enrollment.organization.demo,
          credentials: { create: { tokenHash: digest(raw) } },
        },
      });
      await audit(tx, { orgId: d.orgId }, "device.enroll", d.id);
      await tx.notification.create({
        data: {
          orgId: d.orgId,
          title: "Device enrolled: " + d.hostname,
          link: "/devices",
        },
      });
      return d;
    });
    publish(device.orgId, "devices");
    res
      .status(201)
      .json({
        deviceId: device.id,
        deviceToken: raw,
        eventIds: device.eventIds,
        configVersion: device.configVersion,
        simulated: device.simulated,
      });
  });
  agent.use(async (req, res, next) => {
    const bearer = req.headers.authorization;
    if (!bearer?.startsWith("Bearer ") || bearer.length > 100)
      throw new HttpError(401, "Device credential required");
    const credential = await db.deviceCredential.findUnique({
      where: { tokenHash: digest(bearer.slice(7)) },
      include: { device: true },
    });
    if (!credential || credential.revokedAt || !credential.device.active)
      throw new HttpError(401, "Device credential invalid");
    res.locals.device = credential.device;
    res.locals.credentialId = credential.id;
    next();
  });
  agent.post("/heartbeat", async (req, res) => {
    const v = z
      .object({
        queueDepth: z.number().int().min(0).max(100000),
        error: z.string().max(300).nullable().default(null),
      })
      .strict()
      .parse(req.body);
    const d = res.locals.device;
    await db.$transaction([
      db.device.update({
        where: { id: d.id },
        data: { lastHeartbeat: new Date(), healthError: v.error },
      }),
      db.agentHeartbeat.create({ data: { deviceId: d.id, ...v } }),
    ]);
    publish(d.orgId, "devices");
    res.json({
      eventIds: d.eventIds,
      configVersion: d.configVersion,
      simulated: d.simulated,
    });
  });
  agent.post("/rotate", async (_req, res) => {
    const d = res.locals.device;
    const raw = token();
    await db.$transaction(async (tx) => {
      await tx.deviceCredential.updateMany({
        where: { deviceId: d.id, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      await tx.deviceCredential.create({
        data: { deviceId: d.id, tokenHash: digest(raw) },
      });
      await audit(tx, { orgId: d.orgId }, "credential.rotate", d.id);
    });
    res.json({ deviceToken: raw });
  });
  agent.post("/revoke", async (_req, res) => {
    const d = res.locals.device;
    await db.$transaction(async (tx) => {
      await tx.deviceCredential.updateMany({
        where: { deviceId: d.id },
        data: { revokedAt: new Date() },
      });
      await tx.device.update({ where: { id: d.id }, data: { active: false } });
      await audit(tx, { orgId: d.orgId }, "device.self-revoke", d.id);
    });
    res.json({ ok: true });
  });
  agent.post("/events", async (req, res) => {
    const v = batchSchema.parse(req.body);
    const d = res.locals.device;
    const now = Date.now();
    for (const e of v.events) {
      const t = Date.parse(e.timestamp);
      if (t > now + 300000 || t < now - 30 * 86400000)
        throw new HttpError(
          400,
          "Event timestamp outside accepted 30-day window",
        );
      if (!d.eventIds.includes(e.windowsEventId))
        throw new HttpError(400, "Event excluded by collection policy");
    }
    const result = await db.$transaction(
      async (tx) => {
        await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${d.id}))::text`;
        // Recheck credentials before writing the batch.
        const fresh = await tx.device.findUnique({ where: { id: d.id } });
        const validCredential = await tx.deviceCredential.findFirst({
          where: { id: res.locals.credentialId, revokedAt: null },
        });
        if (!fresh?.active || !validCredential)
          throw new HttpError(401, "Device revoked");
        const policies: Record<string, RulePolicy> = {};
        for (const p of await tx.detectionRule.findMany({
          where: { orgId: d.orgId },
        }))
          policies[p.ruleId] = p.policy as RulePolicy;
        let accepted = 0,
          alertCount = 0;
        for (const incoming of [...v.events].sort(
          (a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp),
        )) {
          const { timestamp, ...fields } = incoming;
          const inserted = await tx.securityEvent.createMany({
            data: [
              {
                ...fields,
                orgId: d.orgId,
                deviceId: d.id,
                timestamp: new Date(timestamp),
                category: category(incoming.windowsEventId),
                outcome: outcome(incoming.windowsEventId),
                simulated: d.simulated,
              },
            ],
            skipDuplicates: true,
          });
          if (!inserted.count) continue;
          accepted++;
          const saved = await tx.securityEvent.findUniqueOrThrow({
            where: {
              deviceId_eventKey: {
                deviceId: d.id,
                eventKey: incoming.eventKey,
              },
            },
          });
          const history = await tx.securityEvent.findMany({
            where: {
              deviceId: d.id,
              orgId: d.orgId,
              timestamp: {
                gte: new Date(Date.parse(timestamp) - 600000),
                lte: new Date(timestamp),
              },
            },
            orderBy: { timestamp: "desc" },
            take: 2000,
          });
          const toEvidence = (e: typeof saved): EvidenceEvent => ({
            ...e,
            timestamp: e.timestamp.toISOString(),
            username: e.username ?? undefined,
            sourceIp: e.sourceIp ?? undefined,
            processName: e.processName ?? undefined,
            metadata: e.metadata as EvidenceEvent["metadata"],
            provider: e.provider as EvidenceEvent["provider"],
          });
          for (const detection of evaluate(
            toEvidence(saved),
            history.map(toEvidence),
            policies,
          )) {
            const suppression =
              policies[detection.ruleId]?.suppressionSeconds ?? 120;
            const duplicate = await tx.detectionAlert.findFirst({
              where: {
                deviceId: d.id,
                ruleId: detection.ruleId,
                groupKey: detection.group,
                eventTimestamp: {
                  gte: new Date(Date.parse(timestamp) - suppression * 1000),
                  lte: new Date(timestamp),
                },
              },
            });
            if (duplicate) continue;
            await tx.detectionAlert.create({
              data: {
                orgId: d.orgId,
                deviceId: d.id,
                ruleId: detection.ruleId,
                name: detection.name,
                severity: detection.severity,
                description: detection.description,
                certainty: detection.certainty,
                eventIds: detection.eventIds,
                techniques: detection.techniques,
                explanation: detection.explanation,
                groupKey: detection.group,
                simulated: d.simulated,
                eventTimestamp: new Date(timestamp),
              },
            });
            alertCount++;
            await tx.notification.create({
              data: {
                orgId: d.orgId,
                title:
                  (d.simulated ? "[SIMULATED] " : "") +
                  detection.name +
                  " on " +
                  d.hostname,
                link: "/threats",
              },
            });
          }
        }
        if (accepted)
          await tx.device.update({
            where: { id: d.id },
            data: { lastEvent: new Date() },
          });
        return {
          accepted,
          duplicates: v.events.length - accepted,
          alerts: alertCount,
        };
      },
      { timeout: 30000 },
    );
    publish(d.orgId, "events");
    res.json(result);
  });
  app.use("/api/agent", agent);
  app.use(
    "/api",
    rateLimit({
      windowMs: 60000,
      limit: 300,
      standardHeaders: "draft-8",
      legacyHeaders: false,
    }),
  );
  app.use("/api", async (req, res, next) => {
    const raw = req.cookies.zeroeye_session;
    if (typeof raw !== "string") throw new HttpError(401, "Sign in required");
    const session = await db.session.findUnique({
      where: { id: digest(raw) },
      include: { user: { select: { id: true, name: true, email: true } } },
    });
    if (!session || session.expiresAt < new Date())
      throw new HttpError(401, "Session expired");
    const memberships = await db.organizationMember.findMany({
      where: { userId: session.userId },
      include: { organization: true },
    });
    const requested = req.headers["x-organization-id"];
    const membership = requested
      ? memberships.find((m) => m.orgId === requested)
      : memberships[0];
    if (!membership) throw new HttpError(403, "Organization access denied");
    res.locals.ctx = {
      userId: session.userId,
      orgId: membership.orgId,
      role: membership.role,
      csrf: session.csrf,
      sessionId: session.id,
    };
    res.locals.user = session.user;
    res.locals.memberships = memberships;
    if (
      !["GET", "HEAD", "OPTIONS"].includes(req.method) &&
      (req.headers.origin !== config.WEB_ORIGIN ||
        req.headers["x-csrf-token"] !== session.csrf)
    )
      throw new HttpError(403, "CSRF validation failed");
    next();
  });
  app.get("/api/auth/me", (_req, res) =>
    res.json({
      user: res.locals.user,
      csrf: context(res).csrf,
      organizations: res.locals.memberships.map((m: any) => ({
        id: m.orgId,
        name: m.organization.name,
        demo: m.organization.demo,
        role: m.role,
      })),
      currentOrganizationId: context(res).orgId,
    }),
  );
  app.post("/api/auth/logout", async (_req, res) => {
    const c = context(res);
    await db.$transaction(async (tx) => {
      await tx.session.deleteMany({ where: { id: c.sessionId } });
      await audit(tx, c, "user.logout", c.userId);
    });
    res.clearCookie("zeroeye_session", {
      path: "/",
      secure: config.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "strict",
    });
    res.json({ ok: true });
  });
  app.post("/api/organizations", async (req, res) => {
    const v = z
      .object({
        name: z.string().trim().min(1).max(100),
        demo: z.boolean().default(false),
      })
      .strict()
      .parse(req.body);
    const c = context(res);
    const org = await db.$transaction(async (tx) => {
      const o = await tx.organization.create({
        data: {
          ...v,
          members: { create: { userId: c.userId, role: "OWNER" } },
          settings: { create: {} },
        },
      });
      await audit(tx, { ...c, orgId: o.id }, "organization.create", o.id);
      return o;
    });
    res.status(201).json(org);
  });
  app.get("/api/organizations/members", async (_req, res) => {
    const c = context(res);
    res.json(
      await db.organizationMember.findMany({
        where: { orgId: c.orgId },
        include: { user: { select: { id: true, name: true, email: true } } },
      }),
    );
  });
  app.post("/api/organizations/members", async (req, res) => {
    admin(res);
    const c = context(res);
    const v = z
      .object({
        email: z
          .string()
          .email()
          .transform((s) => s.toLowerCase()),
        role: z.enum(roles),
      })
      .strict()
      .parse(req.body);
    if (v.role === "OWNER" && c.role !== "OWNER")
      throw new HttpError(403, "Only owners grant ownership");
    const user = await db.user.findUnique({ where: { email: v.email } });
    if (!user) throw new HttpError(404, "User must register first");
    const member = await db.$transaction(async (tx) => {
      const existing = await tx.organizationMember.findUnique({
        where: { orgId_userId: { orgId: c.orgId, userId: user.id } },
      });
      if (existing) throw new HttpError(409, "Member already exists");
      const m = await tx.organizationMember.create({
        data: { orgId: c.orgId, userId: user.id, role: v.role },
      });
      await audit(tx, c, "membership.add", m.id, { role: v.role });
      return m;
    });
    res.status(201).json(member);
  });
  app.get("/api/devices", async (_req, res) =>
    res.json(
      await db.device.findMany({
        where: { orgId: context(res).orgId },
        orderBy: { createdAt: "desc" },
      }),
    ),
  );
  app.post("/api/devices/enrollment-token", async (_req, res) => {
    admin(res);
    const c = context(res);
    const raw = token();
    const expiresAt = new Date(Date.now() + 600000);
    await db.$transaction(async (tx) => {
      const e = await tx.deviceEnrollmentToken.create({
        data: { orgId: c.orgId, tokenHash: digest(raw), expiresAt },
      });
      await audit(tx, c, "enrollment.issue", e.id);
    });
    res.status(201).json({ token: raw, expiresAt });
  });
  app.get("/api/devices/:id", async (req, res) => {
    const d = await db.device.findFirst({
      where: { id: id(req), orgId: context(res).orgId },
    });
    if (!d) throw new HttpError(404, "Device not found");
    res.json(d);
  });
  app.patch("/api/devices/:id", async (req, res) => {
    admin(res);
    const c = context(res);
    const v = z
      .object({
        tags: z.array(z.string().max(40)).max(20).optional(),
        eventIds: z
          .array(
            z
              .number()
              .int()
              .refine((n) => (EVENT_IDS as readonly number[]).includes(n)),
          )
          .min(1)
          .max(10)
          .optional(),
      })
      .strict()
      .parse(req.body);
    const d = await db.$transaction(async (tx) => {
      const count = await tx.device.updateMany({
        where: { id: id(req), orgId: c.orgId },
        data: { ...v, configVersion: { increment: 1 } },
      });
      if (!count.count) throw new HttpError(404, "Device not found");
      await audit(tx, c, "device.configure", id(req));
      return tx.device.findUnique({ where: { id: id(req) } });
    });
    res.json(d);
  });
  app.delete("/api/devices/:id", async (req, res) => {
    admin(res);
    const c = context(res);
    await db.$transaction(async (tx) => {
      const d = await tx.device.findFirst({
        where: { id: id(req), orgId: c.orgId },
      });
      if (!d) throw new HttpError(404, "Device not found");
      await tx.device.update({ where: { id: d.id }, data: { active: false } });
      await tx.deviceCredential.updateMany({
        where: { deviceId: d.id },
        data: { revokedAt: new Date() },
      });
      await audit(tx, c, "device.revoke", d.id);
    });
    publish(c.orgId, "devices");
    res.json({ ok: true });
  });
  const filters = (
    req: Request,
    orgId: string,
  ): Prisma.SecurityEventWhereInput => {
    const v = z
      .object({
        deviceId: z.string().uuid().optional(),
        windowsEventId: z.coerce.number().int().optional(),
        username: z.string().max(256).optional(),
        sourceIp: z.string().ip().optional(),
        category: z
          .enum(["authentication", "account", "process", "audit"])
          .optional(),
        severity: z
          .enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
          .optional(),
        from: z.string().datetime({ offset: true }).optional(),
        to: z.string().datetime({ offset: true }).optional(),
        q: z.string().max(100).optional(),
      })
      .parse(req.query);
    return {
      orgId,
      ...(v.deviceId ? { deviceId: v.deviceId } : {}),
      ...(v.windowsEventId ? { windowsEventId: v.windowsEventId } : {}),
      ...(v.username
        ? { username: { contains: v.username, mode: "insensitive" } }
        : {}),
      ...(v.sourceIp ? { sourceIp: v.sourceIp } : {}),
      ...(v.category ? { category: v.category } : {}),
      ...(v.severity ? { severity: v.severity } : {}),
      timestamp: {
        gte: v.from ? new Date(v.from) : new Date(Date.now() - 86400000),
        ...(v.to ? { lte: new Date(v.to) } : {}),
      },
      ...(v.q
        ? {
            OR: [
              { username: { contains: v.q, mode: "insensitive" } },
              { processName: { contains: v.q, mode: "insensitive" } },
              { eventKey: { contains: v.q, mode: "insensitive" } },
            ],
          }
        : {}),
    };
  };
  app.get("/api/events", async (req, res) => {
    const { page, limit } = pageSchema.parse(req.query);
    const where = filters(req, context(res).orgId);
    const [items, total] = await db.$transaction([
      db.securityEvent.findMany({
        where,
        skip: (page - 1) * limit,
        take: limit,
        orderBy: [{ timestamp: "desc" }, { id: "desc" }],
        include: { device: { select: { hostname: true } } },
      }),
      db.securityEvent.count({ where }),
    ]);
    res.json({ items, total, page, limit });
  });
  app.get("/api/events/export", async (req, res) => {
    const v = z.enum(["csv", "json"]).parse(req.query.format ?? "csv");
    const rows = await db.securityEvent.findMany({
      where: filters(req, context(res).orgId),
      orderBy: { timestamp: "desc" },
      take: 10000,
    });
    await audit(db, context(res), "events.export", undefined, {
      count: rows.length,
      format: v,
    });
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="zeroeye-events.' + v + '"',
    );
    if (v === "json")
      res.json({ bounded: true, maximumRows: 10000, items: rows });
    else
      res
        .type("text/csv")
        .send(
          csv(
            rows.map((e) => ({
              id: e.id,
              deviceId: e.deviceId,
              eventId: e.windowsEventId,
              timestamp: e.timestamp.toISOString(),
              username: e.username,
              sourceIp: e.sourceIp,
              category: e.category,
              simulated: e.simulated,
            })),
          ),
        );
  });
  app.get("/api/events/:id", async (req, res) => {
    const e = await db.securityEvent.findFirst({
      where: { id: id(req), orgId: context(res).orgId },
    });
    if (!e) throw new HttpError(404, "Event not found");
    res.json(e);
  });
  app.get("/api/alerts", async (req, res) => {
    const { page, limit } = pageSchema.parse(req.query);
    const status = z
      .enum(["OPEN", "ACKNOWLEDGED"])
      .optional()
      .parse(req.query.status);
    const severity = z
      .enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
      .optional()
      .parse(req.query.severity);
    const where = {
      orgId: context(res).orgId,
      ...(status ? { status } : {}),
      ...(severity ? { severity } : {}),
    };
    res.json({
      items: await db.detectionAlert.findMany({
        where,
        include: { device: { select: { hostname: true } } },
        orderBy: { detectedAt: "desc" },
        skip: (page - 1) * limit,
        take: limit,
      }),
      total: await db.detectionAlert.count({ where }),
      page,
      limit,
    });
  });
  app.get("/api/alerts/:id", async (req, res) => {
    const c = context(res);
    const a = await db.detectionAlert.findFirst({
      where: { id: id(req), orgId: c.orgId },
    });
    if (!a) throw new HttpError(404, "Alert not found");
    res.json({
      ...a,
      events: await db.securityEvent.findMany({
        where: { id: { in: a.eventIds }, orgId: c.orgId },
      }),
    });
  });
  app.patch("/api/alerts/:id", async (req, res) => {
    analyst(res);
    const c = context(res);
    const v = z
      .object({ status: z.literal("ACKNOWLEDGED") })
      .strict()
      .parse(req.body);
    await db.$transaction(async (tx) => {
      const count = await tx.detectionAlert.updateMany({
        where: { id: id(req), orgId: c.orgId },
        data: v,
      });
      if (!count.count) throw new HttpError(404, "Alert not found");
      await audit(tx, c, "alert.acknowledge", id(req));
    });
    publish(c.orgId, "alerts");
    res.json({ ok: true });
  });
  app.get("/api/rules", async (_req, res) => {
    const policies = await db.detectionRule.findMany({
      where: { orgId: context(res).orgId },
    });
    res.json(
      RULES.map((r) => ({
        ...r,
        policy: policies.find((p) => p.ruleId === r.id)?.policy ?? {
          enabled: true,
        },
      })),
    );
  });
  app.patch("/api/rules/:ruleId", async (req, res) => {
    admin(res);
    const c = context(res);
    const ruleId = z
      .enum([
        "ZE-001",
        "ZE-002",
        "ZE-003",
        "ZE-004",
        "ZE-005",
        "ZE-006",
        "ZE-007",
        "ZE-008",
      ])
      .parse(req.params.ruleId);
    const policy = policySchema.parse(req.body);
    await db.$transaction(async (tx) => {
      await tx.detectionRule.upsert({
        where: { orgId_ruleId: { orgId: c.orgId, ruleId } },
        create: { orgId: c.orgId, ruleId, policy },
        update: { policy },
      });
      await audit(tx, c, "rule.configure", ruleId, policy);
    });
    res.json({ ok: true });
  });
  app.get("/api/incidents", async (req, res) => {
    const { page, limit } = pageSchema.parse(req.query);
    const status = z.enum(statuses).optional().parse(req.query.status);
    const where = { orgId: context(res).orgId, ...(status ? { status } : {}) };
    res.json({
      items: await db.incident.findMany({
        where,
        orderBy: { updatedAt: "desc" },
        skip: (page - 1) * limit,
        take: limit,
      }),
      total: await db.incident.count({ where }),
      page,
      limit,
    });
  });
  app.post("/api/incidents", async (req, res) => {
    analyst(res);
    const c = context(res);
    const v = z.object({ alertId: z.string().uuid() }).strict().parse(req.body);
    const incident = await db.$transaction(async (tx) => {
      const alert = await tx.detectionAlert.findFirst({
        where: { id: v.alertId, orgId: c.orgId },
      });
      if (!alert) throw new HttpError(404, "Alert not found");
      const i = await tx.incident.create({
        data: {
          orgId: c.orgId,
          alertId: alert.id,
          title: alert.name,
          description: alert.explanation,
          severity: alert.severity,
          events: { create: alert.eventIds.map((eventId) => ({ eventId })) },
        },
      });
      await audit(tx, c, "incident.create", i.id);
      return i;
    });
    publish(c.orgId, "incidents");
    res.status(201).json(incident);
  });
  app.get("/api/incidents/:id", async (req, res) => {
    const i = await db.incident.findFirst({
      where: { id: id(req), orgId: context(res).orgId },
      include: {
        events: { include: { event: true } },
        comments: { orderBy: { createdAt: "asc" } },
        investigations: true,
        actions: true,
        alert: true,
      },
    });
    if (!i) throw new HttpError(404, "Incident not found");
    res.json(i);
  });
  app.patch("/api/incidents/:id", async (req, res) => {
    analyst(res);
    const c = context(res);
    const v = z
      .object({
        status: z.enum(statuses).optional(),
        assignedTo: z.string().uuid().nullable().optional(),
        resolutionNotes: z.string().trim().max(5000).optional(),
      })
      .strict()
      .parse(req.body);
    if (v.status === "RESOLVED" && !v.resolutionNotes?.trim())
      throw new HttpError(400, "Resolution notes required");
    if (
      v.assignedTo &&
      !(await db.organizationMember.findUnique({
        where: { orgId_userId: { orgId: c.orgId, userId: v.assignedTo } },
      }))
    )
      throw new HttpError(400, "Assignee must belong to this organization");
    await db.$transaction(async (tx) => {
      const count = await tx.incident.updateMany({
        where: { id: id(req), orgId: c.orgId },
        data: v,
      });
      if (!count.count) throw new HttpError(404, "Incident not found");
      await audit(tx, c, "incident.update", id(req), v);
      await tx.notification.create({
        data: {
          orgId: c.orgId,
          title: "Incident updated: " + (v.status ?? "assignment"),
          link: "/incidents/" + id(req),
        },
      });
    });
    publish(c.orgId, "incidents");
    res.json({ ok: true });
  });
  app.post("/api/incidents/:id/comments", async (req, res) => {
    analyst(res);
    const c = context(res);
    const v = z
      .object({ body: z.string().trim().min(1).max(5000) })
      .strict()
      .parse(req.body);
    const comment = await db.$transaction(async (tx) => {
      if (
        !(await tx.incident.findFirst({
          where: { id: id(req), orgId: c.orgId },
        }))
      )
        throw new HttpError(404, "Incident not found");
      const comment = await tx.incidentComment.create({
        data: { incidentId: id(req), authorId: c.userId, body: v.body },
      });
      await audit(tx, c, "incident.comment", id(req));
      return comment;
    });
    res.status(201).json(comment);
  });
  app.post("/api/incidents/:id/recommendations", async (req, res) => {
    analyst(res);
    const c = context(res);
    const v = z
      .object({
        kind: z.enum([
          "ACCOUNT_REVIEW",
          "IP_BLOCK_REVIEW",
          "CONTAINMENT_GUIDANCE",
          "INVESTIGATION_TASK",
        ]),
        recommendation: z.string().trim().min(1).max(3000),
      })
      .strict()
      .parse(req.body);
    const action = await db.$transaction(async (tx) => {
      if (
        !(await tx.incident.findFirst({
          where: { id: id(req), orgId: c.orgId },
        }))
      )
        throw new HttpError(404, "Incident not found");
      const a = await tx.responseAction.create({
        data: { incidentId: id(req), ...v },
      });
      await audit(tx, c, "response.advisory", a.id);
      return a;
    });
    res.status(201).json(action);
  });
  app.post("/api/incidents/:id/events", async (req, res) => {
    analyst(res);
    const c = context(res);
    const v = z
      .object({ eventIds: z.array(z.string().uuid()).min(1).max(100) })
      .strict()
      .parse(req.body);
    await db.$transaction(async (tx) => {
      if (
        !(await tx.incident.findFirst({
          where: { id: id(req), orgId: c.orgId },
        }))
      )
        throw new HttpError(404, "Incident not found");
      const events = await tx.securityEvent.findMany({
        where: { id: { in: v.eventIds }, orgId: c.orgId },
        select: { id: true },
      });
      if (events.length !== new Set(v.eventIds).size)
        throw new HttpError(404, "Event not found");
      await tx.incidentEvent.createMany({
        data: events.map((e) => ({
          orgId: c.orgId,
          incidentId: id(req),
          eventId: e.id,
        })),
        skipDuplicates: true,
      });
      await audit(tx, c, "incident.attach-events", id(req), {
        count: events.length,
      });
    });
    res.json({ ok: true });
  });
  app.post("/api/ai/investigate", async (req, res) => {
    analyst(res);
    const c = context(res);
    const v = z
      .object({ incidentId: z.string().uuid() })
      .strict()
      .parse(req.body);
    const i = await investigationTools(db, c.orgId).GetIncidentDetails({
      id: v.incidentId,
    });
    if (!i) throw new HttpError(404, "Incident not found");
    if (!config.AI_SERVICE_TOKEN)
      throw new HttpError(503, "Investigation service is not configured");
    const settings = await db.organizationSettings.findUnique({
      where: { orgId: c.orgId },
    });
    const evidence = i.events.map(({ event: e }) => ({
      id: e.id,
      eventId: e.windowsEventId,
      timestamp: e.timestamp.toISOString(),
      outcome: e.outcome,
      simulated: e.simulated,
    }));
    let response: globalThis.Response;
    try {
      response = await fetch(config.AI_SERVICE_URL + "/investigate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + config.AI_SERVICE_TOKEN,
        },
        body: JSON.stringify({
          incidentId: i.id,
          title: i.title,
          evidence,
          externalAllowed: settings?.externalAiEnabled ?? false,
        }),
        signal: AbortSignal.timeout(20000),
      });
    } catch {
      throw new HttpError(503, "Investigation service unavailable");
    }
    if (!response.ok) throw new HttpError(502, "Investigation service failed");
    const result = z
      .object({
        provider: z.string().max(100),
        summary: z.string().max(5000),
        facts: z
          .array(
            z
              .object({
                text: z.string().max(1000),
                evidenceIds: z.array(z.string().uuid()).min(1).max(100),
              })
              .strict(),
          )
          .max(30),
        hypotheses: z.array(z.string().max(1000)).max(20),
        nextSteps: z.array(z.string().max(1000)).max(20),
        limitations: z.array(z.string().max(1000)).max(20),
      })
      .strict()
      .parse(await response.json());
    const ids = new Set(evidence.map((e) => e.id));
    if (result.facts.some((f) => f.evidenceIds.some((e) => !ids.has(e))))
      throw new HttpError(502, "Investigation returned unsupported evidence");
    const record = await db.$transaction(async (tx) => {
      const r = await tx.aIInvestigation.create({
        data: { incidentId: i.id, provider: result.provider, result },
      });
      await audit(tx, c, "ai.investigate", r.id, {
        provider: result.provider,
        evidenceCount: evidence.length,
      });
      return r;
    });
    res.status(201).json(record);
  });
  app.get("/api/ai/investigations/:id", async (req, res) => {
    const r = await db.aIInvestigation.findFirst({
      where: { id: id(req), incident: { orgId: context(res).orgId } },
    });
    if (!r) throw new HttpError(404, "Investigation not found");
    res.json(r);
  });
  async function overview(orgId: string) {
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);
    const onlineSince = new Date(Date.now() - 120000);
    const [
      totalDevices,
      onlineDevices,
      eventsToday,
      activeAlerts,
      criticalIncidents,
      resolvedIncidents,
      healthIssues,
      recentAlerts,
      recentIncidents,
      severities,
    ] = await db.$transaction([
      db.device.count({ where: { orgId, active: true } }),
      db.device.count({
        where: { orgId, active: true, lastHeartbeat: { gte: onlineSince } },
      }),
      db.securityEvent.count({ where: { orgId, receivedAt: { gte: today } } }),
      db.detectionAlert.count({ where: { orgId, status: "OPEN" } }),
      db.incident.count({
        where: {
          orgId,
          severity: "CRITICAL",
          status: { notIn: ["RESOLVED", "FALSE_POSITIVE"] },
        },
      }),
      db.incident.count({ where: { orgId, status: "RESOLVED" } }),
      db.device.count({
        where: { orgId, active: true, healthError: { not: null } },
      }),
      db.detectionAlert.findMany({
        where: { orgId },
        orderBy: { detectedAt: "desc" },
        take: 5,
        include: { device: { select: { hostname: true } } },
      }),
      db.incident.findMany({
        where: { orgId },
        orderBy: { updatedAt: "desc" },
        take: 5,
      }),
      db.detectionAlert.groupBy({
        by: ["severity"],
        where: { orgId, status: "OPEN" },
        orderBy: { severity: "asc" },
        _count: true,
      }),
    ]);
    return {
      totalDevices,
      onlineDevices,
      offlineDevices: totalDevices - onlineDevices,
      eventsToday,
      activeAlerts,
      criticalIncidents,
      resolvedIncidents,
      healthIssues,
      recentAlerts,
      recentIncidents,
      severities,
      timeZone: "UTC",
    };
  }
  app.get("/api/dashboard/overview", async (_req, res) =>
    res.json(await overview(context(res).orgId)),
  );
  app.get("/api/dashboard/trends", async (_req, res) => {
    const orgId = context(res).orgId;
    const since = new Date(Date.now() - 86400000);
    const rows = await db.$queryRaw<
      { hour: Date; events: bigint; failures: bigint }[]
    >`SELECT date_trunc('hour',timestamp) AS hour, count(*) AS events, count(*) FILTER (WHERE "windowsEventId"=4625) AS failures FROM "SecurityEvent" WHERE "orgId"=${orgId} AND timestamp>=${since} GROUP BY hour ORDER BY hour`;
    const byHour = new Map(rows.map((r) => [r.hour.toISOString(), r]));
    const hours = Array.from({ length: 24 }, (_, n) => {
      const hour = new Date(Date.now() - (23 - n) * 3600000);
      hour.setUTCMinutes(0, 0, 0);
      const r = byHour.get(hour.toISOString());
      return {
        hour: hour.toISOString(),
        events: Number(r?.events ?? 0),
        failures: Number(r?.failures ?? 0),
      };
    });
    res.json(hours);
  });
  app.get("/api/notifications", async (_req, res) => {
    const c = context(res);
    res.json(
      await db.notification.findMany({
        where: { orgId: c.orgId },
        orderBy: { createdAt: "desc" },
        take: 100,
        include: { reads: { where: { userId: c.userId } } },
      }),
    );
  });
  app.patch("/api/notifications/:id", async (req, res) => {
    const c = context(res);
    if (
      !(await db.notification.findFirst({
        where: { id: id(req), orgId: c.orgId },
      }))
    )
      throw new HttpError(404, "Notification not found");
    await db.notificationRead.upsert({
      where: {
        notificationId_userId: { notificationId: id(req), userId: c.userId },
      },
      create: { notificationId: id(req), userId: c.userId },
      update: { readAt: new Date() },
    });
    res.json({ ok: true });
  });
  app.get("/api/settings", async (_req, res) =>
    res.json(
      await db.organizationSettings.findUnique({
        where: { orgId: context(res).orgId },
      }),
    ),
  );
  app.patch("/api/settings", async (req, res) => {
    admin(res);
    const c = context(res);
    const v = z
      .object({
        retentionDays: z.number().int().min(7).max(365),
        externalAiEnabled: z.boolean(),
      })
      .strict()
      .parse(req.body);
    await db.$transaction(async (tx) => {
      await tx.organizationSettings.update({
        where: { orgId: c.orgId },
        data: v,
      });
      await audit(tx, c, "settings.update", c.orgId, v);
    });
    res.json({ ok: true });
  });
  app.get("/api/audit", async (req, res) => {
    admin(res);
    const { page, limit } = pageSchema.parse(req.query);
    res.json(
      await db.auditLog.findMany({
        where: { orgId: context(res).orgId },
        orderBy: { createdAt: "desc" },
        take: limit,
        skip: (page - 1) * limit,
      }),
    );
  });
  app.get("/api/reports", async (_req, res) =>
    res.json(
      await db.report.findMany({
        where: { orgId: context(res).orgId },
        orderBy: { createdAt: "desc" },
        take: 50,
      }),
    ),
  );
  app.post("/api/reports/generate", async (req, res) => {
    analyst(res);
    z.object({ kind: z.literal("SECURITY_SUMMARY") })
      .strict()
      .parse(req.body);
    const c = context(res);
    const metrics = await overview(c.orgId);
    const data = JSON.parse(
      JSON.stringify({
        organizationId: c.orgId,
        generatedAt: new Date().toISOString(),
        period: "UTC day and current totals",
        metrics,
      }),
    );
    const report = await db.$transaction(async (tx) => {
      const r = await tx.report.create({
        data: { orgId: c.orgId, kind: "SECURITY_SUMMARY", data },
      });
      await audit(tx, c, "report.generate", r.id);
      return r;
    });
    res.status(201).json(report);
  });
  app.get("/api/reports/:id/export", async (req, res) => {
    const r = await db.report.findFirst({
      where: { id: id(req), orgId: context(res).orgId },
    });
    if (!r) throw new HttpError(404, "Report not found");
    await audit(db, context(res), "report.export", r.id);
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="zeroeye-report.json"',
    );
    res.json(r);
  });
  app.use((_req, res) => res.status(404).json({ error: "Route not found" }));
  app.use(
    (
      err: unknown,
      _req: Request,
      res: Response,
      _next: express.NextFunction,
    ) => {
      if (err instanceof ZodError)
        return res
          .status(400)
          .json({
            error: "Validation failed",
            issues: err.issues.map((i) => ({
              path: i.path,
              message: i.message,
            })),
          });
      if (err instanceof HttpError)
        return res.status(err.status).json({ error: err.message });
      if (
        err instanceof Prisma.PrismaClientKnownRequestError &&
        err.code === "P2002"
      )
        return res.status(409).json({ error: "Record already exists" });
      if ((err as { type?: string }).type === "entity.too.large")
        return res.status(413).json({ error: "Request too large" });
      if (err instanceof SyntaxError)
        return res.status(400).json({ error: "Invalid JSON" });
      log.error(
        { type: (err as Error)?.name, code: (err as { code?: string })?.code },
        "API error",
      );
      res.status(500).json({ error: "Internal server error" });
    },
  );
  return {
    app,
    setPublish: (fn: typeof publish) => {
      publish = fn;
    },
  };
}
