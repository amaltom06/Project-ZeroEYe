import { WebSocketServer, WebSocket } from "ws";
import type { Server } from "node:http";
import type { PrismaClient } from "@prisma/client";
import { digest } from "./security.js";
export function realtime(server: Server, db: PrismaClient, origin: string) {
  const wss = new WebSocketServer({ noServer: true, maxPayload: 1024 });
  const clients = new Map<
    WebSocket,
    { orgId: string; sessionId: string; userId: string }
  >();
  server.on("upgrade", async (req, socket, head) => {
    try {
      const url = new URL(req.url ?? "/", origin);
      if (
        url.pathname !== "/api/live" ||
        req.headers.origin !== origin ||
        clients.size >= 500
      ) {
        socket.destroy();
        return;
      }
      const raw = req.headers.cookie
        ?.split(";")
        .map((s) => s.trim())
        .find((s) => s.startsWith("zeroeye_session="))
        ?.substring(16);
      if (!raw) {
        socket.destroy();
        return;
      }
      const session = await db.session.findUnique({
        where: { id: digest(raw) },
      });
      const orgId = url.searchParams.get("orgId");
      if (
        !session ||
        session.expiresAt < new Date() ||
        !orgId ||
        !(await db.organizationMember.findUnique({
          where: { orgId_userId: { orgId, userId: session.userId } },
        }))
      ) {
        socket.destroy();
        return;
      }
      wss.handleUpgrade(req, socket, head, (ws) => {
        clients.set(ws, {
          orgId,
          sessionId: session.id,
          userId: session.userId,
        });
        ws.on("close", () => clients.delete(ws));
        ws.on("error", () => clients.delete(ws));
        ws.send(JSON.stringify({ type: "connected" }));
      });
    } catch {
      socket.destroy();
    }
  });
  const timer = setInterval(async () => {
    for (const [ws, c] of clients) {
      try {
        const s = await db.session.findUnique({ where: { id: c.sessionId } });
        const m = await db.organizationMember.findUnique({
          where: { orgId_userId: { orgId: c.orgId, userId: c.userId } },
        });
        if (!s || s.expiresAt < new Date() || !m) {
          ws.close(1008);
          clients.delete(ws);
        } else ws.ping();
      } catch {
        ws.close(1011);
      }
    }
  }, 30000);
  timer.unref();
  server.on("close", () => {
    clearInterval(timer);
    for (const ws of clients.keys()) ws.terminate();
    wss.close();
  });
  return (orgId: string, type: string) => {
    for (const [ws, c] of clients)
      if (c.orgId === orgId && ws.readyState === WebSocket.OPEN) {
        if (ws.bufferedAmount > 65536) {
          ws.close(1013);
          continue;
        }
        ws.send(JSON.stringify({ type }));
      }
  };
}
