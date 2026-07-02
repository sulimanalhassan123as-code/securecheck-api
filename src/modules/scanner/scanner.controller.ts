import { Router, Request, Response } from 'express';
import { Queue } from 'bullmq';
import { redisConnection } from '../../config/redis';
import { prisma } from '../../config/db';
import { getClientIp, lookupGeo } from '../../utils/geo.util';

export const scannerRouter = Router();
const webScanQueue = new Queue('web-header-audit-queue', { connection: redisConnection });

scannerRouter.post('/start', async (req: Request, res: Response) => {
  try {
    let { projectId, targetUrl, userId, userEmail, userName } = req.body;
    if (!targetUrl) return res.status(400).json({ error: 'Target Domain URL is required.' });

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
    await webScanQueue.add('analyze-headers', { scanId: scan.id, targetUrl });
    res.status(200).json({ message: 'Audit successfully queued.', scanId: scan.id });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});
