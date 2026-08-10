import { Router, Request, Response } from "express";
import { prisma } from "../config/db";
import crypto from "crypto";

const router = Router();

const ADMIN_KEY = process.env.ADMIN_KEY || "";
const GH_TOKEN = process.env.GITHUB_TOKEN || "";
const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";

async function isAdmin(req: Request): Promise<boolean> {
  const headerKey = req.header("x-admin-key");
  if (headerKey && (headerKey === ADMIN_KEY || headerKey === GH_TOKEN || headerKey === TG_TOKEN)) return true;
  // Also check Telegram bot token and GitHub token from DB
  if (headerKey) {
    try {
      const rows = await prisma.$queryRawUnsafe(
        `SELECT "botToken" FROM "TelegramConfig" WHERE id = 'default' LIMIT 1`
      ) as any[];
      if (rows.length > 0 && rows[0].botToken && headerKey === rows[0].botToken) return true;
      const ghRows = await prisma.$queryRawUnsafe(
        `SELECT "githubToken" FROM "GitHubConfig" WHERE id = 'default' LIMIT 1`
      ) as any[];
      if (ghRows.length > 0 && ghRows[0].githubToken && headerKey === ghRows[0].githubToken) return true;
    } catch {}
  }
  const bearer = req.header("authorization")?.replace("Bearer ", "");
  if (bearer) {
    try {
      const [tsStr, sig] = bearer.split(".");
      const ts = parseInt(tsStr, 10);
      const now = Math.floor(Date.now() / 1000);
      if (now - ts > 900) return false;
      const expected = crypto.createHmac("sha256", ADMIN_KEY).update(`${ADMIN_KEY}:${ts}`).digest("hex");
      return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
    } catch { return false; }
  }
  return false;
}

async function getApifyTokenFromDB(): Promise<string> {
  try {
    const rows = await prisma.$queryRawUnsafe(
      `SELECT "apifyToken" FROM "ApifyConfig" WHERE id = 'default' LIMIT 1`
    ) as any[];
    if (rows.length > 0 && rows[0].apifyToken) return rows[0].apifyToken;
  } catch {}
  return process.env.APIFY_TOKEN || "";
}

router.get("/", async (req, res) => {
  try {
    const apifyToken = await getApifyTokenFromDB();
    res.json({
      success: true,
      status: "ONLINE",
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage().rss,
      platform: process.platform,
      nodeVersion: process.version,
      services: [
        { name: "Scanner Engine", status: "ONLINE" },
        { name: "AI Assistant", status: "ONLINE" },
        { name: "Domain Intelligence", status: "ONLINE" },
        { name: "Technology Intelligence", status: "ONLINE" },
        { name: "API Intelligence", status: "ONLINE" },
        { name: "Payment Lab", status: "ONLINE" },
        { name: "Deep Website Auditor (Apify)", status: apifyToken ? "ONLINE" : "MISSING_TOKEN" },
      ],
    });
  } catch (err) {
    res.status(500).json({ success: false, error: "System monitoring failed" });
  }
});

// POST /api/system/apify-config — store Apify token in DB (admin-only)
router.post("/apify-config", async (req: Request, res: Response) => {
  try {
    if (!(await isAdmin(req))) return res.status(401).json({ success: false, error: "Unauthorized" });
    const { apifyToken } = req.body;
    if (!apifyToken) return res.status(400).json({ success: false, error: "apifyToken is required." });

    const existing = await prisma.$queryRawUnsafe(`SELECT id FROM "ApifyConfig" WHERE id = 'default' LIMIT 1`) as any[];
    if (existing.length > 0) {
      await prisma.$executeRawUnsafe(
        `UPDATE "ApifyConfig" SET "apifyToken" = $1, "updatedAt" = NOW() WHERE id = 'default'`,
        apifyToken
      );
    } else {
      await prisma.$executeRawUnsafe(
        `INSERT INTO "ApifyConfig" (id, "apifyToken", "createdAt", "updatedAt") VALUES ('default', $1, NOW(), NOW())`,
        apifyToken
      );
    }
    res.json({ success: true, message: "Apify token saved. Deep Website Auditor is now ONLINE." });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/system/apify-config — check if Apify is configured (admin-only)
router.get("/apify-config", async (req: Request, res: Response) => {
  try {
    if (!(await isAdmin(req))) return res.status(401).json({ success: false, error: "Unauthorized" });
    const token = await getApifyTokenFromDB();
    res.json({ success: true, hasToken: !!token, tokenPreview: token ? `${token.slice(0, 12)}...` : null });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.get("/keepalive", async (req, res) => {
  try {
    const projectCount = await prisma.project.count();
    res.json({
      success: true,
      awake: true,
      db: "connected",
      projectCount,
      timestamp: new Date().toISOString(),
    });
  } catch (err: any) {
    res.status(500).json({ success: false, awake: true, db: "error", error: err.message });
  }
});

export default router;
