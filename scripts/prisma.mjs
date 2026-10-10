import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
dotenv.config({
  path: fileURLToPath(new URL("../.env", import.meta.url)),
  quiet: true,
});
const child = spawn(
  process.execPath,
  [
    fileURLToPath(
      new URL("../node_modules/prisma/build/index.js", import.meta.url),
    ),
    ...process.argv.slice(2),
  ],
  { stdio: "inherit", env: process.env, windowsHide: true },
);
child.on("exit", (code) => process.exit(code ?? 1));
