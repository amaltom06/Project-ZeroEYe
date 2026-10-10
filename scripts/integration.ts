import { investigationTools } from "../apps/api/src/investigation-tools.js";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { PrismaClient } from "@prisma/client";
import request from "supertest";
import { WebSocket } from "ws";
import { createApp } from "../apps/api/src/app.js";
import { realtime } from "../apps/api/src/realtime.js";
const original = process.env.DATABASE_URL;
if (!original) throw new Error("DATABASE_URL required");
const schema = "test_" + randomUUID().replaceAll("-", "");
assert(/^test_[a-f0-9]{32}$/.test(schema));
const url = new URL(original);
url.searchParams.set("schema", schema);
const db = new PrismaClient({ datasources: { db: { url: url.toString() } } });
const run = (args: string[], env: NodeJS.ProcessEnv) =>
  new Promise<void>((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: "apps/api",
      env,
      stdio: "inherit",
      windowsHide: true,
    });
    child.on("exit", (c) =>
      c === 0 ? resolve() : reject(new Error("Command failed " + c)),
    );
  });
let checks = 0;
function check(condition: unknown, label: string) {
  assert(condition, label);
  checks++;
  console.log("PASS " + label);
}
const origin = process.env.WEB_ORIGIN ?? "http://localhost:5173";
const { app, setPublish } = createApp(db);
const server = createServer(app);
setPublish(realtime(server, db, origin));
try {
  await run(["../../scripts/prisma.mjs", "migrate", "deploy"], {
    ...process.env,
    DATABASE_URL: url.toString(),
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address !== "string");
  const wsBase = "ws://127.0.0.1:" + address.port;
  const user = async (name: string) => {
    const result = await request(app)
      .post("/api/auth/register")
      .set("Origin", origin)
      .send({
        name,
        email: name + "@example.test",
        password: "Test-only-long-password-123",
        organization: name,
      });
    check(result.status === 201, "registration " + name);
    const cookie = result.headers["set-cookie"][0] as string;
    check(
      cookie.includes("HttpOnly") && cookie.includes("SameSite=Strict"),
      "HttpOnly strict session " + name,
    );
    const csrf = result.body.csrf as string;
    const me = await request(app).get("/api/auth/me").set("Cookie", cookie);
    return {
      cookie,
      csrf,
      orgId: me.body.currentOrganizationId as string,
      userId: me.body.user.id as string,
    };
  };
  const a = await user("alpha");
  const b = await user("bravo");
  const viewer = await user("viewer");
  const call = (
    u: typeof a,
    method: "get" | "post" | "patch" | "delete",
    path: string,
    body?: unknown,
  ) => {
    const r = request(app)
      [method](path)
      .set("Cookie", u.cookie)
      .set("Origin", origin)
      .set("X-CSRF-Token", u.csrf)
      .set("X-Organization-ID", u.orgId);
    return body === undefined ? r : r.send(body);
  };
  check(
    (await request(app).get("/api/devices")).status === 401,
    "protected routes reject anonymous users",
  );
  check(
    (
      await request(app)
        .post("/api/auth/login")
        .set("Origin", origin)
        .send({ email: "alpha@example.test", password: "wrong" })
    ).status === 401,
    "incorrect login rejected",
  );
  const login = await request(app)
    .post("/api/auth/login")
    .set("Origin", origin)
    .send({
      email: "alpha@example.test",
      password: "Test-only-long-password-123",
    });
  check(login.status === 200, "correct login accepted");
  check(
    (
      await request(app)
        .get("/api/devices")
        .set("Cookie", a.cookie)
        .set("X-Organization-ID", b.orgId)
    ).status === 403,
    "cross-organization selection denied",
  );
  check(
    (
      await request(app)
        .post("/api/devices/enrollment-token")
        .set("Cookie", a.cookie)
        .set("Origin", origin)
    ).status === 403,
    "missing CSRF rejected",
  );
  check(
    (
      await call(a, "post", "/api/devices/enrollment-token").set(
        "Origin",
        "https://evil.test",
      )
    ).status === 403,
    "foreign origin rejected",
  );
  const tokenResult = await call(a, "post", "/api/devices/enrollment-token");
  const enrollment = tokenResult.body.token;
  const enrollBody = {
    enrollmentToken: enrollment,
    hostname: "test-endpoint",
    osVersion: "Synthetic test harness",
    agentVersion: "0.1.0",
  };
  const concurrent = await Promise.all([
    request(app).post("/api/agent/enroll").send(enrollBody),
    request(app).post("/api/agent/enroll").send(enrollBody),
  ]);
  check(
    concurrent.filter((r) => r.status === 201).length === 1 &&
      concurrent.filter((r) => r.status === 401).length === 1,
    "enrollment token consumed once under concurrency",
  );
  const device = concurrent.find((r) => r.status === 201)!.body;
  const stored = await db.deviceEnrollmentToken.findFirst({
    where: { orgId: a.orgId },
  });
  check(
    stored?.tokenHash !== enrollment && !!stored?.usedAt,
    "enrollment secrets stored as hashes",
  );
  check(
    (await db.deviceCredential.findFirst())?.tokenHash !== device.deviceToken,
    "device credentials stored as hashes",
  );
  const agent = (path: string, body: unknown) =>
    request(app)
      .post("/api/agent" + path)
      .set("Authorization", "Bearer " + device.deviceToken)
      .send(body);
  check(
    (await agent("/heartbeat", { queueDepth: 0 })).status === 200,
    "authenticated heartbeat accepted",
  );
  check(
    (
      await request(app)
        .post("/api/agent/events")
        .set("Authorization", "Bearer invalid")
        .send({ events: [] })
    ).status === 401,
    "invalid device credential rejected",
  );
  const now = Date.now() - 10000;
  const events = Array.from({ length: 5 }, (_, n) => ({
    eventKey: "test-" + n,
    provider: "Microsoft-Windows-Security-Auditing",
    windowsEventId: 4625,
    timestamp: new Date(now + n * 1000).toISOString(),
    username: "test-account",
    sourceIp: "192.0.2.10",
    metadata: {},
  }));
  check(
    (await agent("/events", { events: [{ ...events[0], orgId: b.orgId }] }))
      .status === 400,
    "forged tenant payload rejected",
  );
  check(
    (await agent("/events", { events: [{ ...events[0], simulated: true }] }))
      .status === 400,
    "forged simulation flag rejected",
  );
  check(
    (
      await agent("/events", {
        events: [{ ...events[0], timestamp: "not-a-date" }],
      })
    ).status === 400,
    "invalid timestamps rejected",
  );
  const ingestion = await agent("/events", { events });
  check(
    ingestion.status === 200 &&
      ingestion.body.accepted === 5 &&
      ingestion.body.alerts === 1,
    "batch stored and brute-force alert created",
  );
  const duplicate = await agent("/events", { events });
  check(
    duplicate.body.accepted === 0 &&
      duplicate.body.duplicates === 5 &&
      duplicate.body.alerts === 0,
    "replayed batch deduplicated",
  );
  const storedEvents = await call(a, "get", "/api/events");
  check(storedEvents.body.total === 5, "event explorer returns stored records");
  const eventId = storedEvents.body.items[0].id;
  check(
    (await call(b, "get", "/api/events/" + eventId)).status === 404,
    "cross-tenant event detail denied",
  );
  check(
    (await call(b, "get", "/api/devices/" + device.deviceId)).status === 404,
    "cross-tenant device detail denied",
  );
  check(
    (
      await call(b, "patch", "/api/devices/" + device.deviceId, {
        tags: ["bad"],
      })
    ).status === 404,
    "cross-tenant modification denied",
  );
  const alerts = await call(a, "get", "/api/alerts");
  const alert = alerts.body.items[0];
  check(
    alert.eventIds.length === 5,
    "alert references its five supporting events",
  );
  check(
    (await call(b, "get", "/api/alerts/" + alert.id)).status === 404,
    "cross-tenant alert denied",
  );
  const incident = await call(a, "post", "/api/incidents", {
    alertId: alert.id,
  });
  check(incident.status === 201, "incident created from alert");
  const incidentId = incident.body.id;
  const detail = await call(a, "get", "/api/incidents/" + incidentId);
  check(detail.body.events.length === 5, "incident preserves evidence links");
  check(
    (await call(b, "get", "/api/incidents/" + incidentId)).status === 404,
    "cross-tenant incident denied",
  );
  check(
    (
      await call(a, "patch", "/api/incidents/" + incidentId, {
        assignedTo: b.userId,
      })
    ).status === 400,
    "foreign analyst assignment rejected",
  );
  check(
    (
      await call(a, "post", "/api/incidents/" + incidentId + "/comments", {
        body: "Synthetic test investigation note",
      })
    ).status === 201,
    "analyst note persisted",
  );
  check(
    (
      await call(a, "patch", "/api/incidents/" + incidentId, {
        status: "RESOLVED",
      })
    ).status === 400,
    "resolution requires notes",
  );
  check(
    (
      await call(a, "patch", "/api/incidents/" + incidentId, {
        status: "RESOLVED",
        resolutionNotes: "Synthetic test completed.",
      })
    ).status === 200,
    "incident resolved with notes",
  );
  check(
    (
      await call(a, "patch", "/api/incidents/" + incidentId, {
        status: "INVESTIGATING",
      })
    ).status === 200,
    "incident can reopen",
  );
  check(
    (
      await call(a, "post", "/api/organizations/members", {
        email: "viewer@example.test",
        role: "VIEWER",
      })
    ).status === 201,
    "owner grants viewer membership",
  );
  const asViewer = { ...viewer, orgId: a.orgId };
  check(
    (await call(asViewer, "get", "/api/events")).status === 200,
    "viewer can read organization evidence",
  );
  check(
    (await call(asViewer, "post", "/api/devices/enrollment-token")).status ===
      403,
    "viewer cannot issue enrollment tokens",
  );
  check(
    (
      await call(asViewer, "patch", "/api/settings", {
        retentionDays: 7,
        externalAiEnabled: true,
      })
    ).status === 403,
    "viewer cannot change security settings",
  );
  check(
    (
      await call(asViewer, "patch", "/api/incidents/" + incidentId, {
        status: "FALSE_POSITIVE",
      })
    ).status === 403,
    "viewer cannot change incidents",
  );
  const dashboard = await call(a, "get", "/api/dashboard/overview");
  check(
    dashboard.body.eventsToday === 5 &&
      dashboard.body.onlineDevices === 1 &&
      dashboard.body.activeAlerts === 1,
    "dashboard metrics reflect database state",
  );
  check(
    (await call(b, "get", "/api/dashboard/overview")).body.eventsToday === 0,
    "dashboard tenant isolation",
  );
  check(
    (await call(a, "get", "/api/events/export?format=csv")).text.includes(
      "192.0.2.10",
    ),
    "authorized CSV export",
  );
  check(
    (await call(b, "get", "/api/events/export?format=json")).body.items
      .length === 0,
    "export tenant isolation",
  );
  const report = await call(a, "post", "/api/reports/generate", {
    kind: "SECURITY_SUMMARY",
  });
  check(report.status === 201, "timestamped report generated");
  check(
    (await call(b, "get", "/api/reports/" + report.body.id + "/export"))
      .status === 404,
    "cross-tenant report denied",
  );
  const ws = new WebSocket(wsBase + "/api/live?orgId=" + a.orgId, {
    headers: { Cookie: a.cookie, Origin: origin },
  });
  await new Promise<void>((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
    setTimeout(() => reject(new Error("WebSocket timeout")), 5000).unref();
  });
  check(ws.readyState === WebSocket.OPEN, "authenticated websocket opens");
  ws.close();
  const badWs = new WebSocket(wsBase + "/api/live?orgId=" + b.orgId, {
    headers: { Cookie: a.cookie, Origin: origin },
  });
  const denied = await new Promise<boolean>((resolve) => {
    badWs.once("open", () => {
      badWs.close();
      resolve(false);
    });
    badWs.once("error", () => resolve(true));
    setTimeout(() => resolve(false), 5000).unref();
  });
  check(denied, "websocket tenant isolation");
  if (process.env.TEST_AI === "true") {
    const result = await call(a, "post", "/api/ai/investigate", { incidentId });
    check(
      result.status === 201 && result.body.result.facts.length === 1,
      "real investigation service returns cited evidence",
    );
    check(
      (await call(b, "get", "/api/ai/investigations/" + result.body.id))
        .status === 404,
      "investigation tenant isolation",
    );
  }
  const tools = investigationTools(db, b.orgId);
  check(
    (await tools.GetDeviceDetails({ id: device.deviceId })) === null,
    "read-only device tool enforces tenant",
  );
  check(
    (await tools.GetIncidentDetails({ id: incidentId })) === null,
    "read-only incident tool enforces tenant",
  );
  check(
    (await tools.GetRelatedAlerts({ id: device.deviceId })).length === 0,
    "related-alert tool enforces tenant",
  );
  let forgedTool = false;
  try {
    await tools.GetDeviceDetails({ id: device.deviceId, orgId: a.orgId });
  } catch {
    forgedTool = true;
  }
  check(forgedTool, "read-only tools reject forged tenant fields");
  const demoOrg = await call(a, "post", "/api/organizations", {
    name: "isolated demo test",
    demo: true,
  });
  const inDemo = { ...a, orgId: demoOrg.body.id };
  const demoToken = await call(inDemo, "post", "/api/devices/enrollment-token");
  const demoDevice = await request(app)
    .post("/api/agent/enroll")
    .send({
      ...enrollBody,
      enrollmentToken: demoToken.body.token,
      hostname: "SIMULATED-test-endpoint",
    });
  check(
    demoDevice.body.simulated === true,
    "demo device identity is server-derived",
  );
  const demoEvent = {
    ...events[0],
    eventKey: "demo-clear",
    provider: "Microsoft-Windows-Eventlog",
    windowsEventId: 1102,
  };
  const demoIngest = await request(app)
    .post("/api/agent/events")
    .set("Authorization", "Bearer " + demoDevice.body.deviceToken)
    .send({ events: [demoEvent] });
  check(
    demoIngest.body.alerts === 1,
    "real audit-clear schema triggers demo rule",
  );
  const demoAlerts = await call(inDemo, "get", "/api/alerts");
  check(
    demoAlerts.body.items[0].simulated === true,
    "synthetic detections remain explicitly simulated",
  );
  check(
    (await call(a, "get", "/api/events")).body.total === 5,
    "demo events cannot mix with real organization",
  );
  const runPresentation = (orgId: string) => new Promise<{ code: number | null; output: string }>((resolve, reject) => {
    const child = spawn(process.execPath, ["scripts/demo-live.mjs", "--auto"], {
      cwd: process.cwd(), windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, ZEROEYE_URL: "http://127.0.0.1:" + address.port,
        ZEROEYE_DEMO_EMAIL: "alpha@example.test", ZEROEYE_DEMO_PASSWORD: "Test-only-long-password-123",
        ZEROEYE_DEMO_ORG_ID: orgId },
    });
    let output = "";
    child.stdout.on("data", (chunk) => { output += chunk.toString(); });
    child.stderr.on("data", (chunk) => { output += chunk.toString(); });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, output }));
  });
  const sessionsBeforePresentation = await db.session.count();
  const presentation = await runPresentation(inDemo.orgId);
  if (presentation.code !== 0) console.error(presentation.output);
  check(presentation.code === 0, "staged presentation runs through actual authenticated API");
  check(presentation.output.includes("7 stored simulated events; 3 new detections"), "presentation reports verified event and alert counts");
  const presentationDevice = await db.device.findFirstOrThrow({ where: {
    orgId: inDemo.orgId, hostname: { startsWith: "SIMULATED-PRESENTATION-" },
  } });
  const presentationEvents = await db.securityEvent.findMany({ where: { deviceId: presentationDevice.id } });
  check(presentationEvents.length === 7 && presentationEvents.every((event) => event.simulated), "presentation records remain server-marked simulated");
  const presentationAlerts = await db.detectionAlert.findMany({ where: { deviceId: presentationDevice.id } });
  check(presentationAlerts.length === 3 && presentationAlerts.every((alert) => alert.simulated), "staged failures, success and clearing create three simulated alerts");
  check(presentationAlerts.find((alert) => alert.ruleId === "ZE-001")?.eventIds.length === 5 &&
    presentationAlerts.find((alert) => alert.ruleId === "ZE-008")?.eventIds.length === 6 &&
    presentationAlerts.find((alert) => alert.ruleId === "ZE-005")?.eventIds.length === 1,
    "presentation alerts cite the expected five, six and one evidence records");
  check(presentationDevice.active === false && (await db.deviceCredential.findMany({ where: { deviceId: presentationDevice.id } })).every((credential) => credential.revokedAt !== null), "presentation disables its simulated device credential on exit");
  check(await db.session.count() === sessionsBeforePresentation, "presentation closes only its own login session");
  const realCountBeforePresentation = await db.securityEvent.count({ where: { orgId: a.orgId } });
  const refusedPresentation = await runPresentation(a.orgId);
  check(refusedPresentation.code !== 0 && refusedPresentation.output.includes("LIVE workspaces are refused"), "presentation refuses a live workspace");
  check(await db.securityEvent.count({ where: { orgId: a.orgId } }) === realCountBeforePresentation, "refused live presentation stores no synthetic records");
  const demoIncident = await call(inDemo, "post", "/api/incidents", { alertId: presentationAlerts.find((alert) => alert.ruleId === "ZE-008")!.id });
  check(demoIncident.status === 201 && (await call(inDemo, "get", "/api/incidents/" + demoIncident.body.id)).body.events.length === 6, "presentation detection becomes an incident with six evidence records");
  if (process.env.TEST_AI === "true") {
    const demoInvestigation = await call(inDemo, "post", "/api/ai/investigate", { incidentId: demoIncident.body.id });
    check(demoInvestigation.status === 201 && demoInvestigation.body.result.facts.length === 2 &&
      demoInvestigation.body.result.limitations.some((limitation: string) => limitation.includes("simulated")),
      "presentation investigation cites login evidence and discloses simulation");
  }
  const rotated = await agent("/rotate", {});
  check(rotated.status === 200, "device credential rotation");
  check(
    (await agent("/heartbeat", { queueDepth: 0 })).status === 401,
    "old device credential rejected after rotation",
  );
  check(
    (await call(a, "delete", "/api/devices/" + device.deviceId)).status === 200,
    "administrator revokes device",
  );
  check(
    (
      await request(app)
        .post("/api/agent/heartbeat")
        .set("Authorization", "Bearer " + rotated.body.deviceToken)
        .send({ queueDepth: 0 })
    ).status === 401,
    "revoked device cannot heartbeat",
  );
  const audit = await call(a, "get", "/api/audit");
  check(
    audit.body.some(
      (e: { action: string }) => e.action === "incident.update",
    ) &&
      audit.body.some((e: { action: string }) => e.action === "device.revoke"),
    "security-sensitive actions audited",
  );
  check(
    (await call(a, "post", "/api/auth/logout")).status === 200,
    "logout succeeds",
  );
  check(
    (await call(a, "get", "/api/devices")).status === 401,
    "logged-out session rejected",
  );
  console.log("Integration checks passed: " + checks);
} finally {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  server.closeAllConnections();
  await db.$executeRawUnsafe('DROP SCHEMA IF EXISTS "' + schema + '" CASCADE');
  await db.$disconnect();
}
