import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';
import * as dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';

import { scannerRouter } from './modules/scanner/scanner.controller';
import apiIntelRouter from './routes/apiintel.routes';
import systemRouter from './routes/system.routes';
import { analyzerRouter } from './modules/analyzer/analyzer.controller';
import { deepScanRouter } from './modules/analyzer/deepScan.controller';
import { historyRouter } from './modules/analyzer/history.controller';
import paymentRouter from './routes/payment.routes';
import technologyRouter from './routes/technology.routes';
import domainRouter from './routes/domain.routes';
import { cardsRouter } from './routes/cards.routes';
import { assistantRouter } from './modules/assistant/assistant.controller';
import { assistantV2Router } from './modules/assistant/assistant-v2.controller';
import { schedulerRouter, tickScheduledScans } from './modules/scheduler/scheduler.controller';
import { telegramConfigRouter } from './modules/telegram/telegram.controller';
import { githubRouter, triggerDailySummary } from './modules/github/github.controller';
import { initializeScannerWorker } from './modules/scanner/scanner.worker';
import { runInlineScan } from './modules/scanner/inline-scan';
import { alertCriticalFindings } from './utils/telegram.util';
import { prisma } from './config/db';

dotenv.config();

const app = express();
app.set('trust proxy', true);
const httpServer = createServer(app);

const io = new Server(httpServer, {
  cors: { origin: '*' },
});

const ALLOWED_ORIGINS = [
  'https://securecheck-ui.vercel.app',
  'http://localhost:5173',
  'http://localhost:3000',
];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
}));
app.use(express.json({ limit: '10mb' }));

// ── Rate limiting: protect paid external APIs (Groq, Apify) from abuse
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests. Please try again later.' },
});
app.use('/api', generalLimiter);

const costlyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Rate limit reached for this tool. Please try again in a few minutes.' },
});

// ── Health check root
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'online',
    service: 'SecureCheck AI — Cyber-Zero Vulnerability Scanner API',
    engine: 'Groq Llama 3.3 Versatile Pipeline',
    database: 'PostgreSQL Connected (Supabase)',
    version: '2.3.0',
  });
});

// ── Routes
app.use('/api/scans', costlyLimiter, scannerRouter);
app.use('/api/domain', costlyLimiter, domainRouter);
app.use('/api/apiintel', costlyLimiter, apiIntelRouter);
app.use('/api/system', systemRouter);
app.use('/api/payment', paymentRouter);
app.use('/api/technology', costlyLimiter, technologyRouter);
app.use('/api/analyzer', costlyLimiter, analyzerRouter);
app.use('/api/analyzer', deepScanRouter);
app.use('/api/analyzer', historyRouter);
app.use('/api', cardsRouter);
app.use('/api/assistant', costlyLimiter, assistantRouter);
app.use('/api/assistant-v2', costlyLimiter, assistantV2Router);
app.use('/api/scheduler', schedulerRouter);
// Telegram webhook needs to bypass rate limiting
app.use('/api/telegram', telegramConfigRouter);
// GitHub webhook needs to bypass rate limiting and CORS
app.use('/api/github', githubRouter);

// ── Score Timeline endpoint
app.get('/api/analyzer/score-timeline', async (req, res) => {
  try {
    const targetUrl = req.query.targetUrl as string | undefined;
    if (!targetUrl) return res.status(400).json({ success: false, error: 'targetUrl is required.' });

    const scans = await prisma.scan.findMany({
      where: { targetUrl, status: 'COMPLETED' },
      orderBy: { createdAt: 'asc' },
      take: 50,
      select: {
        id: true,
        securityScore: true,
        createdAt: true,
        scanType: true,
        findings: { select: { severity: true } },
      },
    });

    const timeline = scans.map(s => {
      const critical = s.findings.filter(f => f.severity === 'CRITICAL').length;
      const high = s.findings.filter(f => f.severity === 'HIGH').length;
      return {
        date: s.createdAt,
        score: s.securityScore,
        scanId: s.id,
        criticalCount: critical,
        highCount: high,
        totalFindings: s.findings.length,
      };
    });

    res.json({ success: true, targetUrl, count: timeline.length, timeline });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Scan result by ID (with findings)
app.get('/api/scans/:id', async (req, res) => {
  try {
    const scan = await prisma.scan.findUnique({
      where: { id: req.params.id },
      include: { findings: true },
    });
    if (!scan) return res.status(404).json({ error: 'Scan not found.' });
    res.status(200).json(scan);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start scanner worker after 2s (let DB connect first)
setTimeout(() => {
  initializeScannerWorker(io);
}, 2000);

// ── Scheduled scan runner: triggers a scan for a given URL (used by scheduler tick)
async function runScheduledScan(targetUrl: string): Promise<void> {
  const hasRedis = !!process.env.REDIS_URL;
  const defaultProject = await prisma.project.findFirst({ where: { name: 'Default Test Project' } }) ||
                         await prisma.project.create({ data: { name: 'Default Test Project' } });

  const scan = await prisma.scan.create({
    data: {
      projectId: defaultProject.id, targetUrl, scanType: 'WEB_HEADERS', status: 'QUEUED',
      userId: null, userEmail: null, userName: 'Scheduled Scan',
    },
  });

  if (hasRedis) {
    const { Queue } = await import('bullmq');
    const { redisConnection } = await import('./config/redis');
    const queue = new Queue('web-header-audit-queue', { connection: redisConnection });
    await queue.add('analyze-headers', { scanId: scan.id, targetUrl });
  } else {
    // No Redis — run inline
    const result = await runInlineScan(scan.id, targetUrl);
    // Send Telegram alert after inline scan
    if (result.success) {
      try {
        const scanRecord = await prisma.scan.findUnique({
          where: { id: scan.id },
          include: { findings: { select: { title: true, severity: true } } },
        });
        if (scanRecord) {
          await alertCriticalFindings({
            id: scanRecord.id,
            targetUrl: scanRecord.targetUrl,
            securityScore: scanRecord.securityScore,
            findings: scanRecord.findings,
            userEmail: null,
            userName: 'Scheduled Scan',
          });
        }
      } catch (e: any) {
        console.error('⚠️ Telegram alert after scheduled scan failed:', e.message);
      }
    }
  }
}

// ── Scheduler tick: check every 60s for due scheduled scans
setInterval(() => {
  tickScheduledScans(runScheduledScan);
}, 60_000);

// ── Daily Security Summary: sends a consolidated report of all GitHub repos at 8 AM UTC
let lastDailySummaryDate = '';
setInterval(async () => {
  const now = new Date();
  // 8:00 AM UTC (8 AM Ghana time — Ghana is GMT+0)
  if (now.getUTCHours() === 8 && now.getUTCMinutes() < 5) {
    const todayStr = now.toISOString().split('T')[0];
    if (todayStr !== lastDailySummaryDate) {
      lastDailySummaryDate = todayStr;
      console.log('📋 Triggering daily GitHub security summary...');
      try {
        await triggerDailySummary();
      } catch (e: any) {
        console.error('❌ Daily summary failed:', e.message);
      }
    }
  }
}, 60_000);

// ── Auto-migrate: create tables if they don't exist (runs on every boot)
async function autoMigrate() {
  const tables = [
    {
      name: 'AiQuery',
      sql: `CREATE TABLE IF NOT EXISTS "AiQuery" (
        "id" TEXT NOT NULL DEFAULT gen_random_uuid()::text,
        "userId" TEXT,
        "userEmail" TEXT,
        "intent" TEXT NOT NULL,
        "message" TEXT NOT NULL,
        "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT "AiQuery_pkey" PRIMARY KEY ("id")
      );`,
    },
    {
      name: 'ScheduledScan',
      sql: `CREATE TABLE IF NOT EXISTS "ScheduledScan" (
        "id" TEXT NOT NULL DEFAULT gen_random_uuid()::text,
        "targetUrl" TEXT NOT NULL,
        "label" TEXT,
        "cadence" TEXT NOT NULL DEFAULT 'daily',
        "isActive" BOOLEAN NOT NULL DEFAULT true,
        "lastRunAt" TIMESTAMP(3),
        "nextRunAt" TIMESTAMP(3) NOT NULL,
        "lastScore" INTEGER,
        "createdBy" TEXT,
        "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updatedAt" TIMESTAMP(3) NOT NULL,
        CONSTRAINT "ScheduledScan_pkey" PRIMARY KEY ("id")
      );`,
    },
    {
      name: 'TelegramConfig',
      sql: `CREATE TABLE IF NOT EXISTS "TelegramConfig" (
        "id" TEXT NOT NULL,
        "botToken" TEXT,
        "chatId" TEXT,
        "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updatedAt" TIMESTAMP(3) NOT NULL,
        CONSTRAINT "TelegramConfig_pkey" PRIMARY KEY ("id")
      );`,
    },
    {
      name: 'GitHubConfig',
      sql: `CREATE TABLE IF NOT EXISTS "GitHubConfig" (
        "id" TEXT NOT NULL,
        "webhookSecret" TEXT,
        "githubToken" TEXT,
        "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updatedAt" TIMESTAMP(3) NOT NULL,
        CONSTRAINT "GitHubConfig_pkey" PRIMARY KEY ("id")
      );`,
    },
    {
      name: 'ApifyConfig',
      sql: `CREATE TABLE IF NOT EXISTS "ApifyConfig" (
        "id" TEXT NOT NULL,
        "apifyToken" TEXT,
        "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updatedAt" TIMESTAMP(3) NOT NULL,
        CONSTRAINT "ApifyConfig_pkey" PRIMARY KEY ("id")
      );`,
    },
  ];

  for (const t of tables) {
    try {
      await prisma.$executeRawUnsafe(t.sql);
      console.log(`✅ Auto-migration: ${t.name} table ready`);
    } catch (e: any) {
      console.error(`⚠️ Auto-migration failed (${t.name}):`, e.message);
    }
  }
}

const PORT = process.env.PORT || 5000;
httpServer.listen(PORT, () => {
  console.log(`📡 SecureCheck API v2.3.0 running on port ${PORT}`);
  autoMigrate();
});
