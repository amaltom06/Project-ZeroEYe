import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { randomUUID } from "node:crypto";

// This is a simulated device using the actual enrollment and ingestion APIs.
// It never reads Windows logs or changes a Windows service or audit policy.
const automatic = process.argv.includes("--auto");
const base = process.env.ZEROEYE_URL ?? "http://localhost:4000";
const origin = process.env.WEB_ORIGIN ?? "http://localhost:5173";
const email = process.env.ZEROEYE_DEMO_EMAIL;
let password = process.env.ZEROEYE_DEMO_PASSWORD;
delete process.env.ZEROEYE_DEMO_PASSWORD;
const requestedOrganization = process.env.ZEROEYE_DEMO_ORG_ID;
const prompts = createInterface({ input: stdin, output: stdout });
const stopped = new AbortController();
let cookie;
let csrf;
let organizationId;
let agentHeaders;
let heartbeat;
let accepted = 0;
let detections = 0;

function stop() {
  stopped.abort();
  prompts.close();
}
process.once("SIGINT", stop);
process.once("SIGTERM", stop);

async function question(message) {
  return prompts.question(message, { signal: stopped.signal });
}

async function request(path, payload, headers, method = "POST") {
  const response = await fetch(base + "/api" + path, {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    body: payload === undefined ? undefined : JSON.stringify(payload),
    signal: AbortSignal.timeout(10000),
    redirect: "error",
  });
  if (!response.ok) {
    throw new Error(`Request ${path} failed (HTTP ${response.status}).`);
  }
  return { response, body: await response.json() };
}

function sessionHeaders() {
  return {
    Origin: origin,
    Cookie: cookie,
    "X-CSRF-Token": csrf,
    ...(organizationId ? { "X-Organization-ID": organizationId } : {}),
  };
}

async function pause(message) {
  if (!automatic) await question(message + " Press Enter to continue: ");
  if (stopped.signal.aborted) throw new Error("Demo cancelled.");
}

async function send(events) {
  if (stopped.signal.aborted) throw new Error("Demo cancelled.");
  const { body } = await request("/agent/events", { events }, agentHeaders);
  accepted += body.accepted;
  detections += body.alerts;
  console.log(`Stored ${body.accepted} simulated event(s); new detections: ${body.alerts}.`);
}

try {
  const backend = new URL(base);
  if (
    !["localhost", "127.0.0.1", "[::1]"].includes(backend.hostname) ||
    !["http:", "https:"].includes(backend.protocol) ||
    backend.username || backend.password || backend.pathname !== "/" ||
    backend.search || backend.hash
  ) {
    throw new Error("This presentation utility requires a local backend origin.");
  }
  if (process.argv.slice(2).some((arg) => arg !== "--auto")) {
    throw new Error("Supported option: --auto (noninteractive rehearsal).");
  }
  if (!password) throw new Error("Run npm run demo:live to enter credentials privately.");
  const login = await request("/auth/login", {
    email: email ?? await question("Registered ZEROEYE email: "),
    password,
  }, { Origin: origin });
  password = undefined;
  cookie = login.response.headers.get("set-cookie")?.split(";")[0];
  csrf = login.body.csrf;
  if (!cookie || !csrf) throw new Error("Login did not return a valid session.");
  const { body: me } = await request("/auth/me", undefined, sessionHeaders(), "GET");
  let demos = me.organizations.filter(
    (org) => org.demo && ["OWNER", "ADMIN"].includes(org.role),
  );
  if (!demos.length && !automatic && !requestedOrganization) {
    const consent = await question("Create a separate DEMO workspace named ZEROEYE Presentation? Type CREATE: ");
    if (consent !== "CREATE") throw new Error("Create or select a DEMO workspace before running this demonstration.");
    const { body: org } = await request("/organizations", {
      name: "ZEROEYE Presentation", demo: true,
    }, sessionHeaders());
    demos = [{ ...org, role: "OWNER" }];
  }
  if (!demos.length) throw new Error("An Owner/Admin membership in a DEMO workspace is required.");
  let selected;
  if (requestedOrganization) {
    selected = demos.find((org) => org.id === requestedOrganization);
  } else if (demos.length === 1) {
    selected = demos[0];
  } else if (!automatic) {
    demos.forEach((org, index) => console.log(`${index}: ${org.name} [DEMO]`));
    const answer = (await question("DEMO workspace number: ")).trim();
    if (/^\d+$/.test(answer)) selected = demos[Number(answer)];
  }
  if (!selected) throw new Error("Select an Owner/Admin DEMO workspace. LIVE workspaces are refused.");
  organizationId = selected.id;
  console.log(`\nWorkspace: ${selected.name} [DEMO]`);
  console.log("SIMULATED activity through real enrollment, storage and detection APIs.");
  console.log("Open http://localhost:5173 and select this workspace. No real endpoint is monitored.\n");
  await pause("Show the Overview and Devices pages before enrollment.");
  const { body: enrollment } = await request("/devices/enrollment-token", {}, sessionHeaders());
  const { body: device } = await request("/agent/enroll", {
    enrollmentToken: enrollment.token,
    hostname: "SIMULATED-PRESENTATION-" + randomUUID().slice(0, 6),
    osVersion: "Synthetic presentation endpoint",
    agentVersion: "0.1.0",
  }, {});
  agentHeaders = { Authorization: "Bearer " + device.deviceToken };
  if (!device.simulated) throw new Error("Refusing to send sample events for a real device.");
  await request("/agent/heartbeat", { queueDepth: 0, error: null }, agentHeaders);
  heartbeat = setInterval(() => {
    request("/agent/heartbeat", { queueDepth: 0, error: null }, agentHeaders)
      .catch(() => console.log("Demo heartbeat unavailable; check the API and device status."));
  }, 30000);
  console.log("Simulated device enrolled. Devices should show a reporting endpoint.");

  // Fixed, labeled scenario timestamps preserve its ordering while the presenter pauses.
  const stamp = Date.now() - 60000;
  const sample = (windowsEventId, offset) => ({
    eventKey: randomUUID(),
    provider: windowsEventId === 1102
      ? "Microsoft-Windows-Eventlog"
      : "Microsoft-Windows-Security-Auditing",
    windowsEventId,
    timestamp: new Date(stamp + offset).toISOString(),
    username: "presentation-account",
    sourceIp: "192.0.2.25",
    metadata: windowsEventId === 1102 ? {} : { logonType: "3" },
  });

  console.log("\nSTAGE 1: five failed logins (4625).");
  await pause("Open Live Events. After the fifth failure, open Threat Detection.");
  for (let index = 0; index < 5; index++) {
    await send([sample(4625, index * 5000)]);
    if (!automatic && index < 4) await new Promise((resolve) => setTimeout(resolve, 1200));
  }
  console.log("Expected with default rules: Repeated failed logons (HIGH), citing five events.");

  console.log("\nSTAGE 2: successful login after the failures (4624).");
  await pause("Explain that the pattern requires checking the account owner and source.");
  await send([sample(4624, 30000)]);
  console.log("Expected with default rules: Success after repeated failures (HIGH), citing six events.");

  console.log("\nSTAGE 3: sample Security-log-clearing record (1102).");
  await pause("This sends a sample record. The actual Windows Security log is never cleared.");
  await send([sample(1102, 35000)]);
  console.log("Expected with default rules: Security audit log cleared (CRITICAL).");
  const { body: events } = await request(
    "/events?deviceId=" + encodeURIComponent(device.deviceId) + "&limit=100",
    undefined, sessionHeaders(), "GET",
  );
  if (events.total !== 7 || !events.items.every((event) => event.simulated)) {
    throw new Error("Stored scenario verification failed; review Live Events.");
  }
  console.log(`\nVerified scenario: ${accepted} stored simulated events; ${detections} new detections.`);
  console.log("With unchanged default rules, the scenario produces three alerts.");
  console.log("Open an alert -> Create incident -> Investigate evidence -> add a note -> resolve with notes.");
  console.log("The current investigator computes evidence summaries; no language model is enabled.");
  await pause("Finish presenting. Ending the demo disables its device credential and preserves evidence.");
} catch (error) {
  console.error(stopped.signal.aborted ? "Demo cancelled." : "Demo stopped: " + error.message);
  if (!stopped.signal.aborted) process.exitCode = 1;
} finally {
  clearInterval(heartbeat);
  if (agentHeaders) {
    try {
      await request("/agent/revoke", {}, agentHeaders);
      console.log("Simulated device credential disabled; historical records remain in the DEMO workspace.");
    } catch {
      console.error("Could not disable the simulated credential. Revoke this demo device in Devices.");
      process.exitCode = 1;
    }
  }
  if (cookie && csrf) {
    try { await request("/auth/logout", {}, sessionHeaders()); }
    catch { console.error("Demo session cleanup unavailable; it will expire normally."); }
  }
  password = undefined;
  prompts.close();
  process.removeListener("SIGINT", stop);
  process.removeListener("SIGTERM", stop);
}
