import { Router } from "express";

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

export default router;
