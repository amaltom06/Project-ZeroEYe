import EmbeddedPostgres from "embedded-postgres";
import { mkdir, readFile, writeFile, access } from "node:fs/promises";
import { randomBytes } from "node:crypto";
await mkdir(".runtime", { recursive: true });
let password;
try {
  password = await readFile(".runtime/db-password", "utf8");
} catch {
  password = randomBytes(32).toString("hex");
  await writeFile(".runtime/db-password", password, { mode: 0o600 });
}
const pg = new EmbeddedPostgres({
  databaseDir: ".runtime/postgres",
  user: "zeroeye",
  password,
  port: 54329,
  persistent: true,
  authMethod: "scram-sha-256",
  initdbFlags: ["--auth=scram-sha-256", "--encoding=UTF8"],
  postgresFlags: ["-c", "listen_addresses=127.0.0.1"],
});
try {
  await access(".runtime/postgres/PG_VERSION");
} catch {
  await pg.initialise();
}
await pg.start();
const client = pg.getPgClient();
await client.connect();
const exists = await client.query(
  "SELECT 1 FROM pg_database WHERE datname='zeroeye'",
);
await client.end();
if (!exists.rowCount) await pg.createDatabase("zeroeye");
try {
  await access(".env");
} catch {
  await writeFile(
    ".env",
    "NODE_ENV=development\nHOST=127.0.0.1\nPORT=4000\nWEB_ORIGIN=http://localhost:5173\nDATABASE_URL=postgresql://zeroeye:" +
      password +
      "@127.0.0.1:54329/zeroeye\nAI_SERVICE_URL=http://127.0.0.1:8000\nAI_SERVICE_TOKEN=" +
      randomBytes(32).toString("hex") +
      "\n",
  );
}
console.log(
  "Local PostgreSQL ready on 127.0.0.1:54329. Keep this terminal open. Credentials are in ignored local files.",
);
let stopping = false;
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, async () => {
    if (stopping) return;
    stopping = true;
    await pg.stop();
    process.exit(0);
  });
setInterval(() => {}, 60000);
