import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { randomUUID } from "node:crypto";
const prompts = createInterface({ input: stdin, output: stdout });
const base = process.env.ZEROEYE_URL ?? "http://localhost:4000";
const origin = process.env.WEB_ORIGIN ?? "http://localhost:5173";
try {
  const email = await prompts.question("Registered email: ");
  const password = process.env.ZEROEYE_DEMO_PASSWORD;
  if (!password)
    throw new Error(
      "Set ZEROEYE_DEMO_PASSWORD for this process, then clear it after use. See docs/demo.md.",
    );
  const login = await fetch(base + "/api/auth/login", {
    method: "POST",
    headers: { Origin: origin, "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!login.ok) throw new Error("Login failed");
  const data = await login.json();
  const cookie = login.headers.get("set-cookie").split(";")[0];
  const me = await fetch(base + "/api/auth/me", {
    headers: { Cookie: cookie },
  }).then((r) => r.json());
  const demos = me.organizations.filter((o) => o.demo);
  if (!demos.length)
    throw new Error("Create an isolated demo organization in Settings first.");
  demos.forEach((o, n) => console.log(n + ": " + o.name));
  const choice = Number(await prompts.question("Demo organization index: "));
  const org = demos[choice];
  if (!org) throw new Error("Invalid choice");
  const headers = {
    Origin: origin,
    Cookie: cookie,
    "Content-Type": "application/json",
    "X-CSRF-Token": data.csrf,
    "X-Organization-ID": org.id,
  };
  const post = async (path, payload, h = headers) => {
    const r = await fetch(base + "/api" + path, {
      method: "POST",
      headers: h,
      body: JSON.stringify(payload),
    });
    if (!r.ok) throw new Error("Request failed " + r.status);
    return r.json();
  };
  const enrollment = await post("/devices/enrollment-token", {});
  const device = await post("/agent/enroll", {
    enrollmentToken: enrollment.token,
    hostname: "SIMULATED-WINDOWS-" + randomUUID().slice(0, 6),
    osVersion: "Synthetic demo endpoint",
    agentVersion: "0.1.0",
  });
  if (!device.simulated)
    throw new Error("Refusing to generate events for a real device");
  const agentHeaders = {
    Authorization: "Bearer " + device.deviceToken,
    "Content-Type": "application/json",
  };
  await post("/agent/heartbeat", { queueDepth: 0, error: null }, agentHeaders);
  const stamp = Date.now() - 60000;
  const events = Array.from({ length: 5 }, (_, n) => ({
    eventKey: randomUUID(),
    provider: "Microsoft-Windows-Security-Auditing",
    windowsEventId: 4625,
    timestamp: new Date(stamp + n * 5000).toISOString(),
    username: "demo-account",
    sourceIp: "192.0.2.25",
    metadata: { logonType: "3" },
  }));
  events.push({
    ...events[0],
    eventKey: randomUUID(),
    windowsEventId: 4624,
    timestamp: new Date(stamp + 30000).toISOString(),
  });
  events.push({
    ...events[0],
    eventKey: randomUUID(),
    windowsEventId: 1102,
    provider: "Microsoft-Windows-Eventlog",
    timestamp: new Date(stamp + 35000).toISOString(),
  });
  const result = await post("/agent/events", { events }, agentHeaders);
  console.log(
    "SIMULATED demo records ingested: " +
      result.accepted +
      "; detections: " +
      result.alerts +
      ". No real endpoint was monitored.",
  );
  await post("/auth/logout", {});
} finally {
  prompts.close();
  delete process.env.ZEROEYE_DEMO_PASSWORD;
}
