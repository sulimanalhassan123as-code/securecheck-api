import { Router, Request, Response } from 'express';
import { Queue } from 'bullmq';
import { redisConnection } from '../../config/redis';
import { prisma } from '../../config/db';

export const scannerRouter = Router();
const webScanQueue = new Queue('web-header-audit-queue', { connection: redisConnection });

scannerRouter.post('/start', async (req: Request, res: Response) => {
  try {
    const { projectId, targetUrl } = req.body;
    if (!targetUrl) return res.status(400).json({ error: 'Target Domain URL is required.' });
    const scan = await prisma.scan.create({
      data: { projectId, targetUrl, scanType: 'WEB_HEADERS', status: 'QUEUED' }
    });
    await webScanQueue.add('analyze-headers', { scanId: scan.id, targetUrl });
    res.status(200).json({ message: 'Audit successfully queued.', scanId: scan.id });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});
