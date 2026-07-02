import { Router, Request, Response } from 'express';
import Groq from 'groq-sdk';
import { prisma } from '../../config/db';
import { crawlWebsiteWithApify } from './apify.service';
import { buildSiteIntelReport } from './siteIntel.service';
import { getClientIp, lookupGeo } from '../../utils/geo.util';

export const deepScanRouter = Router();

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY || '' });

const DEEP_SYSTEM_PROMPT = `You are Cyber-Zero's elite deep website intelligence & penetration-testing analyst.
You are given structured recon data collected from a live website: crawled pages, detected technologies,
missing security headers, exposed secrets found in public JS/CSS files, robots.txt, and page metadata.

Analyze it like a real security researcher would: understand the site's logic/purpose, its tech stack risk profile,
and produce concrete, realistic findings. Do NOT invent vulnerabilities that aren't supported by the evidence,
but DO reason about what the evidence implies (e.g. missing CSP -> XSS risk; exposed key -> credential leak).

Respond with STRICT JSON matching exactly:
{
  "securityScore": 0-100,
  "siteSummary": "short paragraph describing what the site is/does and its stack",
  "findings": [
    {
      "title": "String",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
      "confidence": "HIGH | MEDIUM | LOW",
      "description": "String",
      "riskExplanation": "String",
      "attackScenario": "String",
      "affectedComponent": "String",
      "lineNumber": 0,
      "recommendation": "String",
      "secureCodeExample": "String",
      "checklistSteps": ["String"]
    }
  ]
}`;

deepScanRouter.post('/deep-scan', async (req: Request, res: Response) => {
  try {
    let { projectId, targetUrl, userId, userEmail, userName } = req.body;
    if (!targetUrl) return res.status(400).json({ error: 'targetUrl is required.' });
    try {
      new URL(targetUrl);
    } catch {
      return res.status(400).json({ error: 'targetUrl is not a valid URL.' });
    }

    if (!projectId) {
      const defaultProject =
        (await prisma.project.findFirst({ where: { name: 'Default Test Project' } })) ||
        (await prisma.project.create({ data: { name: 'Default Test Project' } }));
      projectId = defaultProject.id;
    }

    const ip = getClientIp(req);
    const userAgent = (req.headers['user-agent'] as string) || null;
    const geo = await lookupGeo(ip);

    const scan = await prisma.scan.create({
      data: {
        projectId, targetUrl, scanType: 'DEEP_WEBSITE_AUDIT', status: 'PROCESSING',
        userId: userId || null,
        userEmail: userEmail || null,
        userName: userName || null,
        ipAddress: ip,
        userAgent,
        city: geo.city,
        country: geo.country,
      },
    });

    const startTime = Date.now();

    // Step 1: crawl the site with Apify (multi-page recon). Fall back gracefully if it fails.
    let crawledPages: { url: string; text?: string; html?: string; title?: string }[] = [];
    let crawlError: string | null = null;
    try {
      crawledPages = await crawlWebsiteWithApify(targetUrl, 8);
    } catch (err: any) {
      crawlError = err.message;
    }

    // Step 2: build the site intelligence report (headers, tech stack, exposed secrets, assets)
    const report = await buildSiteIntelReport(targetUrl, crawledPages);

    // Step 3: send the compiled recon to Groq for deep reasoning
    const userPayload = {
      targetUrl: report.targetUrl,
      finalUrl: report.finalUrl,
      statusCode: report.statusCode,
      pageTitle: report.pageTitle,
      metaDescription: report.metaDescription,
      technologiesDetected: report.technologies,
      missingSecurityHeaders: report.missingSecurityHeaders,
      exposedSecretsFound: report.exposedSecrets,
      publicAssetsScanned: report.assetsScanned,
      robotsTxtPresent: !!report.robotsTxt,
      sitemapReferenced: report.sitemapFound,
      crawledPages: report.crawledSummaries,
      crawlNote: crawlError ? `Apify crawl unavailable: ${crawlError}` : `Crawled ${report.crawledPageCount} pages via Apify.`,
    };

    const aiResponse = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: DEEP_SYSTEM_PROMPT },
        { role: 'user', content: JSON.stringify(userPayload) },
      ],
      response_format: { type: 'json_object' },
    });

    const parsedText = aiResponse.choices[0]?.message?.content;
    if (!parsedText) throw new Error('Empty response from deep-analysis AI pipeline.');
    const aiResult = JSON.parse(parsedText);

    const duration = Date.now() - startTime;

    await prisma.$transaction(async (tx) => {
      if (aiResult.findings?.length > 0) {
        await tx.finding.createMany({
          data: aiResult.findings.map((f: any) => ({
            title: f.title,
            severity: f.severity,
            confidence: f.confidence || 'HIGH',
            description: f.description,
            riskExplanation: f.riskExplanation,
            attackScenario: f.attackScenario,
            affectedComponent: f.affectedComponent || 'Website',
            lineNumber: f.lineNumber || 0,
            recommendation: f.recommendation,
            secureCodeExample: f.secureCodeExample || '',
            checklistSteps: f.checklistSteps || [],
            scanId: scan.id,
          })),
        });
      }
      await tx.scan.update({
        where: { id: scan.id },
        data: { status: 'COMPLETED', securityScore: Math.max(0, Math.min(100, aiResult.securityScore ?? 50)), durationMs: duration },
      });
    });

    res.status(200).json({
      message: 'Deep website intelligence audit complete.',
      scanId: scan.id,
      securityScore: aiResult.securityScore,
      siteSummary: aiResult.siteSummary,
      technologies: report.technologies,
      missingSecurityHeaders: report.missingSecurityHeaders,
      exposedSecrets: report.exposedSecrets,
      crawledPageCount: report.crawledPageCount,
      pageTitle: report.pageTitle,
      findings: aiResult.findings,
    });
  } catch (err: any) {
    console.error('❌ DEEP SCAN FAILED:', err);
    res.status(500).json({ error: err.message });
  }
});

