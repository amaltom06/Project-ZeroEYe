import dotenv from "dotenv";
dotenv.config({ path: [".env", "../../.env"], quiet: true });
import { z } from "zod";
export const config = z
  .object({
    NODE_ENV: z
      .enum(["development", "test", "production"])
      .default("development"),
    PORT: z.coerce.number().int().min(1).default(4000),
    HOST: z.string().default("127.0.0.1"),
    WEB_ORIGIN: z.string().url().default("http://localhost:5173"),
    DATABASE_URL: z.string().min(1),
    SESSION_HOURS: z.coerce.number().min(1).max(24).default(12),
    AI_SERVICE_URL: z.string().url().default("http://127.0.0.1:8000"),
    AI_SERVICE_TOKEN: z.string().optional(),
  })
  .parse(process.env);
if (
  config.NODE_ENV === "production" &&
  !config.WEB_ORIGIN.startsWith("https://")
)
  throw new Error("Production requires HTTPS WEB_ORIGIN");
