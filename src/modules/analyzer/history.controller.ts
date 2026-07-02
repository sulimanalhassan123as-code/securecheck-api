import { Router, Request, Response } from 'express';
import { prisma } from '../../config/db';

export const historyRouter = Router();

const ADMIN_KEY = 'sc-owner-2026-nh';

// GET /api/analyzer/history?limit=20&targetUrl=optional
// Lists past deep + quick scans with a severity breakdown and score trend vs
// the previous scan for the same target — powers the Scan History panel.
historyRouter.get('/history', async (req: Request, res: Response) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 20, 100);
    const targetUrl = req.query.targetUrl as string | undefined;

    const scans = await prisma.scan.findMany({
      where: targetUrl ? { targetUrl } : undefined,
      orderBy: { createdAt: 'desc' },
      take: limit,
      include: {
        findings: { select: { severity: true } },
      },
    });

    // Group by targetUrl to compute score deltas between consecutive scans
    const byTarget: Record<string, typeof scans> = {};
    for (const s of scans) {
      const key = s.targetUrl || 'unknown';
      byTarget[key] = byTarget[key] || [];
      byTarget[key].push(s);
    }

    const result = scans.map((s) => {
      const severityCounts = s.findings.reduce((acc: Record<string, number>, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      }, {});

      const sameTarget = byTarget[s.targetUrl || 'unknown'];
      const idx = sameTarget.findIndex((x) => x.id === s.id);
      const prev = sameTarget[idx + 1]; // next in desc order = older scan
      const scoreDelta = prev ? s.securityScore - prev.securityScore : null;

      return {
        id: s.id,
        targetUrl: s.targetUrl,
        scanType: s.scanType,
        status: s.status,
        securityScore: s.securityScore,
        scoreDelta,
        durationMs: s.durationMs,
        findingsCount: s.findings.length,
        severityCounts,
        createdAt: s.createdAt,
      };
    });

    res.json({ success: true, count: result.length, scans: result });
  } catch (err: any) {
    console.error('❌ HISTORY FETCH FAILED:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/analyzer/scan/:id — full findings detail for one past scan (used
// to re-open a historical report without re-running the scan).
historyRouter.get('/scan/:id', async (req: Request, res: Response) => {
  try {
    const scan = await prisma.scan.findUnique({
      where: { id: req.params.id },
      include: { findings: true },
    });
    if (!scan) return res.status(404).json({ success: false, error: 'Scan not found.' });
    res.json({ success: true, scan });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// DELETE /api/analyzer/history — admin-only, wipes ALL scan + finding records.
// Requires header x-admin-key matching the shared owner key.
historyRouter.delete('/history', async (req: Request, res: Response) => {
  try {
    const adminKey = req.header('x-admin-key');
    if (adminKey !== ADMIN_KEY) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    const findingsDeleted = await prisma.finding.deleteMany({});
    const scansDeleted = await prisma.scan.deleteMany({});

    res.json({
      success: true,
      deleted: scansDeleted.count,
      findingsDeleted: findingsDeleted.count,
    });
  } catch (err: any) {
    console.error('❌ HISTORY CLEAR FAILED:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});
