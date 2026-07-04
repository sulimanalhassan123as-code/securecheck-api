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
import { initializeScannerWorker } from './modules/scanner/scanner.worker';
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
    version: '2.2.0',
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

// ── Scan result by ID
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

const PORT = process.env.PORT || 5000;
httpServer.listen(PORT, () => {
  console.log(`📡 SecureCheck API v2.2.0 running on port ${PORT}`);
});
