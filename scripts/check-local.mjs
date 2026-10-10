const checks = [
  ["dashboard", "http://localhost:5173"],
  ["api", "http://127.0.0.1:4000/api/health"],
  ["investigation service", "http://127.0.0.1:8000/health"],
];
for (const [name, url] of checks) {
  const r = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (!r.ok) throw new Error(name + " returned " + r.status);
  console.log(name + ": HTTP " + r.status);
}
