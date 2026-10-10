import { spawn } from "node:child_process";
import dotenv from "dotenv";
import { resolve } from "node:path";
dotenv.config({ quiet: true });
const python =
  process.env.ZEROEYE_PYTHON ??
  resolve(
    ".runtime/python/" +
      (process.platform === "win32" ? "Scripts/python.exe" : "bin/python"),
  );
const child = spawn(
  python,
  ["-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"],
  {
    cwd: "apps/ai-service",
    stdio: "inherit",
    env: process.env,
    windowsHide: true,
  },
);
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => child.kill(signal));
child.on("exit", (c) => process.exit(c ?? 1));
