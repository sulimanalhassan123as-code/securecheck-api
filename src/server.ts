import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';
import * as dotenv from 'dotenv';

// Capacity control management layer
async function enforceMemberCap(req: any, res: any, next: any) {
  const MAX_ALLOWED_MEMBERS = 50;
  try {
    const totalUsers = await prisma.user.count();
    if (totalUsers >= MAX_ALLOWED_MEMBERS) {
      return res.status(403).json({ error: "Registration capacity reached. Access is restricted." });
    }
    next();
  } catch (err) {
    res.status(500).json({ error: "Failed to verify current server traffic load." });
  }
}

import { scannerRouter } from './modules/scanner/scanner.controller';
import { analyzerRouter } from './modules/analyzer/analyzer.controller';
import { initializeScannerWorker } from './modules/scanner/scanner.worker';
import { prisma } from './config/db';

dotenv.config();
const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, { cors: { origin: '*' } });

app.use(cors({ origin: process.env.FRONTEND_URL || "*", credentials: true }));
app.use(express.json());

// Main entry point fix to greet browser visitors cleanly
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
app.use('/api/analyzer', analyzerRouter);

app.get('/api/scans/:id', async (req, res) => {
  try {
    const scan = await prisma.scan.findUnique({ where: { id: req.params.id }, include: { findings: true } });
    if (!scan) return res.status(404).json({ error: 'Report entry layout not found.' });
    res.status(200).json(scan);
  } catch (err: any) { res.status(500).json({ error: err.message }); }
});

setTimeout(() => { initializeScannerWorker(io); }, 2000);
const PORT = process.env.PORT || 5000;
httpServer.listen(PORT, () => console.log(`📡 SecureCheck API running smoothly on port ${PORT}`));
