import { Router, Request, Response } from 'express';
import { prisma } from '../../config/db';

export const historyRouter = Router();

const ADMIN_KEY = 'sc-owner-2026-nh';

function isAdmin(req: Request) {
  return req.header('x-admin-key') === ADMIN_KEY;
}

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
    if (!isAdmin(req)) {
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

// GET /api/analyzer/activity — admin-only feed of who scanned what, from
// where, and on what device/user identity. Powers the Admin Ops dashboard.
historyRouter.get('/activity', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    const limit = Math.min(Number(req.query.limit) || 50, 200);

    const scans = await prisma.scan.findMany({
      orderBy: { createdAt: 'desc' },
      take: limit,
      select: {
        id: true,
        targetUrl: true,
        scanType: true,
        status: true,
        securityScore: true,
        createdAt: true,
        userId: true,
        userEmail: true,
        userName: true,
        ipAddress: true,
        userAgent: true,
        city: true,
        country: true,
      },
    });

    res.json({ success: true, count: scans.length, activity: scans });
  } catch (err: any) {
    console.error('❌ ACTIVITY FETCH FAILED:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/analyzer/users — admin-only. Builds a distinct list of every user
// seen across scans (from Scan.userId/userEmail/userName), merged with their
// ban status from the User table, plus a lifetime scan count.
historyRouter.get('/users', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    const scans = await prisma.scan.findMany({
      where: { userEmail: { not: null } },
      select: {
        userId: true,
        userEmail: true,
        userName: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    const byEmail: Record<string, { userId: string | null; userEmail: string; userName: string | null; scanCount: number; lastSeen: Date }> = {};
    for (const s of scans) {
      const email = s.userEmail!;
      if (!byEmail[email]) {
        byEmail[email] = { userId: s.userId, userEmail: email, userName: s.userName, scanCount: 0, lastSeen: s.createdAt };
      }
      byEmail[email].scanCount += 1;
    }

    const bannedUsers = await prisma.user.findMany({ where: { isBanned: true } });
    const bannedByEmail: Record<string, { banReason: string | null; bannedAt: Date | null }> = {};
    for (const u of bannedUsers) {
      bannedByEmail[u.email] = { banReason: u.banReason, bannedAt: u.bannedAt };
    }

    const users = Object.values(byEmail).map((u) => ({
      ...u,
      isBanned: !!bannedByEmail[u.userEmail],
      banReason: bannedByEmail[u.userEmail]?.banReason || null,
      bannedAt: bannedByEmail[u.userEmail]?.bannedAt || null,
    }));

    res.json({ success: true, count: users.length, users });
  } catch (err: any) {
    console.error('❌ USERS FETCH FAILED:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/analyzer/users/ban — admin-only. Body: { email, reason }.
// Blocks that user from running any scan (quick or deep) until unbanned.
historyRouter.post('/users/ban', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    const { email, reason } = req.body;
    if (!email) return res.status(400).json({ success: false, error: 'email is required.' });

    const user = await prisma.user.upsert({
      where: { email },
      update: { isBanned: true, banReason: reason || null, bannedAt: new Date() },
      create: { email, isBanned: true, banReason: reason || null, bannedAt: new Date() },
    });

    res.json({ success: true, user });
  } catch (err: any) {
    console.error('❌ BAN USER FAILED:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/analyzer/users/unban — admin-only. Body: { email }.
historyRouter.post('/users/unban', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, error: 'email is required.' });

    const user = await prisma.user.upsert({
      where: { email },
      update: { isBanned: false, banReason: null, bannedAt: null },
      create: { email, isBanned: false },
    });

    res.json({ success: true, user });
  } catch (err: any) {
    console.error('❌ UNBAN USER FAILED:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});
