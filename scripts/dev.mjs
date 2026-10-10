import { spawn } from "node:child_process";
import "dotenv/config";
const npm = process.env.npm_execpath;
if (!npm) throw new Error("Start with npm run dev");
const children = ["@zeroeye/api", "@zeroeye/web"].map((workspace) =>
  spawn(process.execPath, [npm, "run", "dev", "--workspace", workspace], {
    stdio: "inherit",
    windowsHide: true,
  }),
);
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => {
    for (const child of children) child.kill(signal);
  });
for (const child of children)
  child.on("exit", (code) => {
    if (code) for (const other of children) other.kill();
  });
