import { Router } from "express";
import { prisma } from "../config/db";

const router = Router();

router.get("/", async (req, res) => {
  try {
    res.json({
      success: true,
      status: "ONLINE",
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage().rss,
      platform: process.platform,
      nodeVersion: process.version,
      services: [
        {
          name: "Scanner Engine",
          status: "ONLINE"
        },
        {
          name: "AI Assistant",
          status: "ONLINE"
        },
        {
          name: "Domain Intelligence",
          status: "ONLINE"
        },
        {
          name: "Technology Intelligence",
          status: "ONLINE"
        },
        {
          name: "API Intelligence",
          status: "ONLINE"
        },
        {
          name: "Payment Lab",
          status: "ONLINE"
        },
        {
          name: "Deep Website Auditor (Apify)",
          status: process.env.APIFY_TOKEN ? "ONLINE" : "MISSING_TOKEN"
        }
      ]
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: "System monitoring failed"
    });
  }
});

// Lightweight keep-alive endpoint: touches Postgres (Supabase) so it doesn't
// go idle, and being an HTTP hit keeps this Render instance from spinning down.
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
