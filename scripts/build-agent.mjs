import { spawn } from "node:child_process";
import { resolve } from "node:path";
if (process.platform !== "win32")
  throw new Error("Agent packaging requires Windows");
const python =
  process.env.ZEROEYE_PYTHON ?? resolve(".runtime/python/Scripts/python.exe");
const run = (args) =>
  new Promise((resolve, reject) => {
    const child = spawn(python, args, { stdio: "inherit", windowsHide: true });
    child.on("exit", (c) =>
      c === 0 ? resolve() : reject(new Error("Packaging failed " + c)),
    );
  });
for (const [name, file] of [
  ["ZeroEye-Agent", "main.py"],
  ["ZeroEye-Service", "service.py"],
])
  await run([
    "-m",
    "PyInstaller",
    "--noconfirm",
    "--clean",
    "--onedir",
    "--name",
    name,
    "--distpath",
    "agents/windows/dist",
    "--workpath",
    ".runtime/pyinstaller/" + name,
    "--specpath",
    ".runtime/pyinstaller",
    "--paths",
    "agents/windows/src",
    "--hidden-import",
    "win32timezone",
    "--hidden-import",
    "win32serviceutil",
    "--hidden-import",
    "servicemanager",
    "agents/windows/src/" + file,
  ]);
console.log(
  "Agent executables built. Installer still requires Inno Setup and clean-machine install/uninstall validation.",
);
