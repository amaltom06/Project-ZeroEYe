import pino from "pino";
export const log = pino({
  level: process.env.NODE_ENV === "test" ? "silent" : "info",
  redact: ["password", "token", "authorization", "cookie"],
});
