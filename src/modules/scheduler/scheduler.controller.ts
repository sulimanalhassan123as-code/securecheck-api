import { Router, Request, Response } from 'express';
import { prisma } from '../../config/db';
import crypto from 'crypto';

export const schedulerRouter = Router();

const ADMIN_KEY = process.env.ADMIN_KEY || '';

function isAdmin(req: Request): boolean {
  const headerKey = req.header('x-admin-key');
  const bearer = req.header('authorization')?.replace('Bearer ', '');
  if (headerKey && headerKey === ADMIN_KEY) return true;
  if (bearer) {
    try {
      const [tsStr, sig] = bearer.split('.');
      const ts = parseInt(tsStr, 10);
      const now = Math.floor(Date.now() / 1000);
      if (now - ts > 900) return false;
      const expected = crypto.createHmac('sha256', ADMIN_KEY).update(`${ADMIN_KEY}:${ts}`).digest('hex');
      return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
    } catch { return false; }
  }
  return false;
}

function computeNextRun(cadence: string, from: Date = new Date()): Date {
  const next = new Date(from);
  switch (cadence) {
    case 'hourly':
      next.setHours(next.getHours() + 1);
      break;
    case 'weekly':
      next.setDate(next.getDate() + 7);
      break;
    case 'daily':
    default:
      next.setDate(next.getDate() + 1);
      break;
  }
  return next;
}

// POST /api/scheduler — create a scheduled scan (admin-only)
schedulerRouter.post('/', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const { targetUrl, label, cadence } = req.body;
    if (!targetUrl) return res.status(400).json({ success: false, error: 'targetUrl is required.' });

    const validCadences = ['hourly', 'daily', 'weekly'];
    const c = validCadences.includes(cadence) ? cadence : 'daily';

    const scheduled = await prisma.scheduledScan.create({
      data: {
        targetUrl,
        label: label || null,
        cadence: c,
        nextRunAt: computeNextRun(c),
        createdBy: req.header('x-admin-key') ? 'admin' : null,
      },
    });
    res.json({ success: true, scheduled });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/scheduler — list all scheduled scans (admin-only)
schedulerRouter.get('/', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const scans = await prisma.scheduledScan.findMany({
      orderBy: { createdAt: 'desc' },
    });
    res.json({ success: true, count: scans.length, scheduled: scans });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// PATCH /api/scheduler/:id — toggle active or update cadence (admin-only)
schedulerRouter.patch('/:id', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const { id } = req.params;
    const { isActive, cadence } = req.body;

    const update: any = {};
    if (typeof isActive === 'boolean') update.isActive = isActive;
    if (cadence && ['hourly', 'daily', 'weekly'].includes(cadence)) {
      update.cadence = cadence;
      update.nextRunAt = computeNextRun(cadence);
    }

    const updated = await prisma.scheduledScan.update({ where: { id }, data: update });
    res.json({ success: true, scheduled: updated });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// DELETE /api/scheduler/:id — delete a scheduled scan (admin-only)
schedulerRouter.delete('/:id', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const { id } = req.params;
    await prisma.scheduledScan.delete({ where: { id } });
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Cron tick: called every 60s by the server to check for due scans
export async function tickScheduledScans(runScanFn: (targetUrl: string) => Promise<void>): Promise<void> {
  try {
    const now = new Date();
    const due = await prisma.scheduledScan.findMany({
      where: { isActive: true, nextRunAt: { lte: now } },
    });

    for (const scheduled of due) {
      console.log(`⏰ Triggering scheduled scan for ${scheduled.targetUrl}`);
      try {
        await runScanFn(scheduled.targetUrl);

        // Update last run and compute next
        const nextRun = computeNextRun(scheduled.cadence);
        await prisma.scheduledScan.update({
          where: { id: scheduled.id },
          data: { lastRunAt: now, nextRunAt: nextRun },
        });
      } catch (err: any) {
        console.error(`❌ Scheduled scan failed for ${scheduled.targetUrl}:`, err.message);
        // Still advance the next run to avoid retry storm
        const nextRun = computeNextRun(scheduled.cadence);
        await prisma.scheduledScan.update({
          where: { id: scheduled.id },
          data: { lastRunAt: now, nextRunAt: nextRun },
        });
      }
    }
  } catch (err: any) {
    console.error('❌ Scheduler tick failed:', err.message);
  }
}
