import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';
import * as dotenv from 'dotenv';
import { scannerRouter } from './modules/scanner/scanner.controller';
import { analyzerRouter } from './modules/analyzer/analyzer.controller';
import { initializeScannerWorker } from './modules/scanner/scanner.worker';
import { prisma } from './config/db';

dotenv.config();
const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use('/api/scans', scannerRouter);
app.use('/api/analyzer', analyzerRouter);

app.get('/api/scans/:id', async (req, res) => {
  try {
    const scan = await prisma.scan.findUnique({ where: { id: req.params.id }, include: { findings: true } });
    if (!scan) return res.status(404).json({ error: 'Report entry layout not found.' });
    res.status(200).json(scan);
  } catch (err: any) { res.status(500).json({ error: err.message }); }
});

initializeScannerWorker(io);
const PORT = process.env.PORT || 5000;
httpServer.listen(PORT, () => console.log(`📡 SecureCheck API running smoothly on port ${PORT}`));
