import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';
import * as dotenv from 'dotenv';

import { scannerRouter } from './modules/scanner/scanner.controller';
import apiIntelRouter from './routes/apiintel.routes';
import systemRouter from './routes/system.routes';
import { analyzerRouter } from './modules/analyzer/analyzer.controller';
import { deepScanRouter } from './modules/analyzer/deepScan.controller';
import { historyRouter } from './modules/analyzer/history.controller';
import paymentRouter from './routes/payment.routes';
import technologyRouter from './routes/technology.routes';
import domainRouter from './routes/domain.routes';
import { assistantRouter } from './modules/assistant/assistant.controller';
import { assistantV2Router } from './modules/assistant/assistant-v2.controller';
import { initializeScannerWorker } from './modules/scanner/scanner.worker';
import { prisma } from './config/db';

dotenv.config();

const app = express();
const httpServer = createServer(app);

const io = new Server(httpServer, {
  cors: { origin: '*' },
});

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));

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
app.use('/api/scans', scannerRouter);
app.use('/api/domain', domainRouter);
app.use('/api/apiintel', apiIntelRouter);
app.use('/api/system', systemRouter);
app.use('/api/payment', paymentRouter);
app.use('/api/technology', technologyRouter);
app.use('/api/analyzer', analyzerRouter);
app.use('/api/analyzer', deepScanRouter);
app.use('/api/analyzer', historyRouter);
app.use('/api/assistant', assistantRouter);
app.use('/api/assistant-v2', assistantV2Router);

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
