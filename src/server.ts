import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';
import * as dotenv from 'dotenv';

import { scannerRouter } from './modules/scanner/scanner.controller';
import apiIntelRouter from "./routes/apiintel.routes";
import { analyzerRouter } from './modules/analyzer/analyzer.controller';
import paymentRouter from "./routes/payment.routes";
import technologyRouter from "./routes/technology.routes";
import domainRouter from "./routes/domain.routes";
import { assistantRouter } from './modules/assistant/assistant.controller';
import { assistantV2Router } from './modules/assistant/assistant-v2.controller';
import { initializeScannerWorker } from './modules/scanner/scanner.worker';
import { prisma } from './config/db';

dotenv.config();

const app = express();
const httpServer = createServer(app);

const io = new Server(httpServer, {
  cors: { origin: '*' }
});

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json());

app.get('/', (req, res) => {
  res.status(200).json({
    status: "online",
    service: "SecureCheck Vulnerability Scanner API Engine",
    engine: "Groq Llama 3.3 Versatile Pipeline",
    database: "PostgreSQL Connected (Supabase Session Pooler)",
    version: "1.0.0"
  });
});

app.use('/api/scans', scannerRouter);
app.use('/api/domain', domainRouter);
app.use('/api/apiintel', apiIntelRouter);
app.use('/api/payment', paymentRouter);
app.use('/api/technology', technologyRouter);
app.use('/api/analyzer', analyzerRouter);
app.use('/api/assistant', assistantRouter);
app.use('/api/assistant-v2', assistantV2Router);

app.get('/api/scans/:id', async (req, res) => {
  try {
    const scan = await prisma.scan.findUnique({
      where: { id: req.params.id },
      include: { findings: true }
    });

    if (!scan) {
      return res.status(404).json({
        error: 'Report entry layout not found.'
      });
    }

    res.status(200).json(scan);

  } catch (err: any) {
    res.status(500).json({
      error: err.message
    });
  }
});

setTimeout(() => {
  initializeScannerWorker(io);
}, 2000);

const PORT = process.env.PORT || 5000;

httpServer.listen(PORT, () => {
  console.log(`📡 SecureCheck API running smoothly on port ${PORT}`);
});
