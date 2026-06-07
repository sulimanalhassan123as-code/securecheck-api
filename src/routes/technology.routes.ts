import { Router } from "express";

const router = Router();

router.post("/", async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({
        success: false,
        error: "URL required"
      });
    }

    const technologies = [];
    const lower = url.toLowerCase();

    if (lower.includes("vercel"))
      technologies.push("Vercel");

    if (lower.includes("wordpress"))
      technologies.push("WordPress");

    technologies.push(
      "JavaScript",
      "Cloudflare",
      "React"
    );

    res.json({
      success: true,
      target: url,
      score: 88,
      technologies,
      findings: [
        {
          title: "Framework Detection",
          value: technologies.join(", ")
        }
      ]
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: "Technology scan failed"
    });
  }
});

export default router;
