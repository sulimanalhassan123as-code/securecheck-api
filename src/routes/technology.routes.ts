import { Router } from 'express';
import Groq from 'groq-sdk';
import { buildSiteIntelReport } from '../modules/analyzer/siteIntel.service';

const router = Router();
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY || '' });

const INSIGHTS_PROMPT = `You are Cyber-Zero's technology stack intelligence analyst. You are given real recon data
collected live from a website: detected technologies, response headers, missing security headers, public JS/CSS
assets that were checked, robots.txt/sitemap presence, and page metadata.

Write a genuine, specific analysis — never generic filler. Reference the ACTUAL technologies and headers found.
If very little was detected, say so honestly and explain what that implies (e.g. server-rendered, obfuscated, or a
minimal static site) rather than inventing detail.

Respond with STRICT JSON matching exactly:
{
  "architectureSummary": "2-3 sentences describing the real stack/hosting/CDN setup found",
  "securityPostureNote": "1-2 sentences on what the missing/present security headers actually imply for this site",
  "confidence": "HIGH | MEDIUM | LOW",
  "categorizedStack": {
    "frontend": ["String"],
    "hostingOrCdn": ["String"],
    "analyticsOrThirdParty": ["String"],
    "other": ["String"]
  }
}`;

router.post('/', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, error: 'URL required' });
    try {
      new URL(url);
    } catch {
      return res.status(400).json({ success: false, error: 'URL is not valid' });
    }

    let report;
    try {
      report = await buildSiteIntelReport(url, []);
    } catch (e) {
      return res.status(500).json({ success: false, error: 'Could not fetch target URL' });
    }

    const reconPayload = {
      targetUrl: report.targetUrl,
      finalUrl: report.finalUrl,
      statusCode: report.statusCode,
      pageTitle: report.pageTitle,
      metaDescription: report.metaDescription,
      technologiesDetected: report.technologies,
      missingSecurityHeaders: report.missingSecurityHeaders,
      responseHeaders: report.headers,
      assetsScanned: report.assetsScanned,
      robotsTxtPresent: !!report.robotsTxt,
      sitemapReferenced: report.sitemapFound,
    };

    let aiResult: any = {
      architectureSummary: 'AI analysis unavailable — showing raw detection data only.',
      securityPostureNote: '',
      confidence: 'LOW',
      categorizedStack: { frontend: [], hostingOrCdn: [], analyticsOrThirdParty: [], other: report.technologies },
    };

    try {
      const aiResponse = await groq.chat.completions.create({
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: INSIGHTS_PROMPT },
          { role: 'user', content: JSON.stringify(reconPayload) },
        ],
        response_format: { type: 'json_object' },
      });
      const parsed = aiResponse.choices[0]?.message?.content;
      if (parsed) aiResult = JSON.parse(parsed);
    } catch (e) {
      // Fall back to raw detection data if the AI pipeline fails — never fake it.
    }

    const headerCoverage = 6 - report.missingSecurityHeaders.length; // out of 6 tracked headers
    const score = Math.min(100, Math.round(50 + report.technologies.length * 4 + headerCoverage * 5));

    res.json({
      success: true,
      target: url,
      finalUrl: report.finalUrl,
      score,
      technologies: report.technologies.length > 0 ? report.technologies : ['No known signatures detected'],
      missingSecurityHeaders: report.missingSecurityHeaders,
      assetsScanned: report.assetsScanned,
      pageTitle: report.pageTitle,
      insights: aiResult,
    });
  } catch (err) {
    console.error('❌ TECH SCAN FAILED:', err);
    res.status(500).json({ success: false, error: 'Technology scan failed' });
  }
});

export default router;
