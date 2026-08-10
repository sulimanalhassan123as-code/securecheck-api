import { Router, Request, Response } from 'express';
import { Queue } from 'bullmq';
import { redisConnection } from '../../config/redis';
import { prisma } from '../../config/db';
import { getClientIp, lookupGeo } from '../../utils/geo.util';
import { checkUserBanned } from '../../utils/banCheck.util';
import { runInlineScan } from './inline-scan';
import { crawlWebsiteWithApify } from '../analyzer/apify.service';
import { buildSiteIntelReport } from '../analyzer/siteIntel.service';
import Groq from 'groq-sdk';

export const scannerRouter = Router();

// Only create the BullMQ queue if Redis is configured
const hasRedis = !!process.env.REDIS_URL;
const webScanQueue = hasRedis ? new Queue('web-header-audit-queue', { connection: redisConnection }) : null;

scannerRouter.post('/start', async (req: Request, res: Response) => {
  try {
    let { projectId, targetUrl, userId, userEmail, userName, scanType } = req.body;
    if (!targetUrl) return res.status(400).json({ error: 'Target Domain URL is required.' });

    // Route DEEP_AUDIT scans to the deep scan pipeline (Apify + AI)
    if (scanType === 'DEEP_AUDIT') {
      return runDeepAudit(req, res);
    }

    const banStatus = await checkUserBanned(userEmail);
    if (banStatus.banned) {
      return res.status(403).json({
        error: `Your account has been restricted from using SecureCheck.${banStatus.reason ? ' Reason: ' + banStatus.reason : ''}`,
      });
    }

    // If no projectId is passed, automatically use or create a default test project
    if (!projectId) {
      const defaultProject = await prisma.project.findFirst({ where: { name: 'Default Test Project' } }) || 
                             await prisma.project.create({ data: { name: 'Default Test Project' } });
      projectId = defaultProject.id;
    }

    const ip = getClientIp(req);
    const userAgent = req.headers['user-agent'] || null;
    const geo = await lookupGeo(ip);

    const scan = await prisma.scan.create({
      data: {
        projectId, targetUrl, scanType: 'WEB_HEADERS', status: 'QUEUED',
        userId: userId || null,
        userEmail: userEmail || null,
        userName: userName || null,
        ipAddress: ip,
        userAgent: userAgent as string | null,
        city: geo.city,
        country: geo.country,
      }
    });

    if (hasRedis && webScanQueue) {
      // Redis available — queue the scan for async processing
      await webScanQueue.add('analyze-headers', { scanId: scan.id, targetUrl });
      res.status(200).json({ message: 'Audit successfully queued.', scanId: scan.id, mode: 'queued' });
    } else {
      // No Redis — run scan inline and return results immediately
      const result = await runInlineScan(scan.id, targetUrl);
      res.status(200).json({ 
        message: result.success ? 'Audit completed.' : 'Audit failed.', 
        scanId: scan.id, 
        mode: 'inline',
        ...result 
      });
    }
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Deep Audit Pipeline (Apify crawl + AI analysis) ───
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

async function runDeepAudit(req: Request, res: Response) {
  try {
    let { projectId, targetUrl, userId, userEmail, userName } = req.body;
    try { new URL(targetUrl); } catch { return res.status(400).json({ error: 'targetUrl is not a valid URL.' }); }

    const banStatus = await checkUserBanned(userEmail);
    if (banStatus.banned) {
      return res.status(403).json({ error: `Your account has been restricted from using SecureCheck.${banStatus.reason ? ' Reason: ' + banStatus.reason : ''}` });
    }

    if (!projectId) {
      const defaultProject = (await prisma.project.findFirst({ where: { name: 'Default Test Project' } })) ||
                             (await prisma.project.create({ data: { name: 'Default Test Project' } }));
      projectId = defaultProject.id;
    }

    const ip = getClientIp(req);
    const userAgent = (req.headers['user-agent'] as string) || null;
    const geo = await lookupGeo(ip);

    const scan = await prisma.scan.create({
      data: {
        projectId, targetUrl, scanType: 'DEEP_WEBSITE_AUDIT', status: 'PROCESSING',
        userId: userId || null, userEmail: userEmail || null, userName: userName || null,
        ipAddress: ip, userAgent, city: geo.city, country: geo.country,
      },
    });

    const startTime = Date.now();

    // Step 1: Crawl the site with Apify
    let crawledPages: { url: string; text?: string; html?: string; title?: string }[] = [];
    let crawlError: string | null = null;
    try {
      crawledPages = await crawlWebsiteWithApify(targetUrl, 8);
    } catch (err: any) {
      crawlError = err.message;
    }

    // Step 2: Build site intelligence report
    const report = await buildSiteIntelReport(targetUrl, crawledPages);

    // Step 3: Send compiled recon to Groq for deep reasoning
    const groq = new Groq({ apiKey: process.env.GROQ_API_KEY || '' });
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
            title: f.title, severity: f.severity, confidence: f.confidence || 'HIGH',
            description: f.description, riskExplanation: f.riskExplanation,
            attackScenario: f.attackScenario, affectedComponent: f.affectedComponent || 'Website',
            lineNumber: f.lineNumber || 0, recommendation: f.recommendation,
            secureCodeExample: f.secureCodeExample || '', checklistSteps: f.checklistSteps || [],
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
      scanId: scan.id, mode: 'deep_audit', success: true,
      score: Math.max(0, Math.min(100, aiResult.securityScore ?? 50)),
      findings: aiResult.findings?.length || 0,
      duration: Math.round(duration / 1000),
      siteSummary: aiResult.siteSummary,
      technologies: report.technologies,
      missingSecurityHeaders: report.missingSecurityHeaders,
      exposedSecrets: report.exposedSecrets,
      crawledPageCount: report.crawledPageCount,
      crawlNote: crawlError ? `Apify crawl unavailable: ${crawlError}` : `Crawled ${report.crawledPageCount} pages via Apify.`,
    });
  } catch (err: any) {
    console.error('❌ DEEP AUDIT FAILED:', err);
    res.status(500).json({ error: err.message, success: false });
  }
}
