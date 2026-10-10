import { createServer } from "node:http";
import { log } from "./logger.js";
import { config } from "./config.js";
import { db } from "./db.js";
import { createApp } from "./app.js";
import { realtime } from "./realtime.js";
const { app, setPublish } = createApp(db);
const server = createServer(app);
setPublish(realtime(server, db, config.WEB_ORIGIN));
await db.$connect();
server.listen(config.PORT, config.HOST, () =>
  log.info({ port: config.PORT }, "ZEROEYE API ready"),
);
let stopping = false;
for (const signal of ["SIGINT", "SIGTERM"] as const)
  process.on(signal, () => {
    if (stopping) return;
    stopping = true;
    server.close(async () => {
      await db.$disconnect();
      process.exit(0);
    });
    setTimeout(() => {
      server.closeAllConnections();
      process.exit(1);
    }, 10000).unref();
  });
