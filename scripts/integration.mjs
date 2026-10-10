import { spawn } from "node:child_process";
import dotenv from "dotenv";
dotenv.config({ quiet: true });
process.env.NODE_ENV = "test";
process.env.TEST_AI = "true";
const child = spawn(
  process.execPath,
  ["node_modules/tsx/dist/cli.mjs", "scripts/integration.ts"],
  { stdio: "inherit", env: process.env, windowsHide: true },
);
child.on("exit", (c) => process.exit(c ?? 1));
