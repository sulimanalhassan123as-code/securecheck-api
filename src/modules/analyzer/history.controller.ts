import { Router, Request, Response } from 'express';
import { prisma } from '../../config/db';
import crypto from 'crypto';

export const historyRouter = Router();

const ADMIN_KEY = process.env.ADMIN_KEY || '';

// ── New HMAC-based admin token system ──
// Issues a short-lived token (15 min) bound to the admin key.
// Old static-key requests are rejected — the key was rotated.
function makeAdminToken(): string {
  const ts = Math.floor(Date.now() / 1000);
  const payload = `${ADMIN_KEY}:${ts}`;
  const sig = crypto.createHmac('sha256', ADMIN_KEY).update(payload).digest('hex');
  return `${ts}.${sig}`;
}

function verifyAdminToken(token: string): boolean {
  try {
    const [tsStr, sig] = token.split('.');
    const ts = parseInt(tsStr, 10);
    const now = Math.floor(Date.now() / 1000);
    if (now - ts > 900) return false;
    const expected = crypto.createHmac('sha256', ADMIN_KEY).update(`${ADMIN_KEY}:${ts}`).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch {
    return false;
  }
}

function isAdmin(req: Request): boolean {
  const headerKey = req.header('x-admin-key');
  const bearer = req.header('authorization')?.replace('Bearer ', '');
  if (headerKey && headerKey === ADMIN_KEY) return true;
  if (bearer && verifyAdminToken(bearer)) return true;
  return false;
}

// POST /api/analyzer/auth/admin — exchange admin key for a short-lived token
historyRouter.post('/auth/admin', (req: Request, res: Response) => {
  const { key } = req.body;
  if (!key || key !== ADMIN_KEY) {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }
  const token = makeAdminToken();
  res.json({ success: true, token, expiresIn: 900 });
});

// GET /api/analyzer/history — USER-ISOLATED
// Non-admins only see their own scans. Must pass userEmail or userId.
historyRouter.get('/history', async (req: Request, res: Response) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 20, 100);
    const userEmail = req.query.userEmail as string | undefined;
    const userId = req.query.userId as string | undefined;
    const targetUrl = req.query.targetUrl as string | undefined;

    let where: any = {};
    if (isAdmin(req)) {
      if (targetUrl) where.targetUrl = targetUrl;
    } else {
      if (userEmail) {
        where.userEmail = userEmail;
      } else if (userId) {
        where.userId = userId;
      } else {
        return res.json({ success: true, count: 0, scans: [] });
      }
      if (targetUrl) where.targetUrl = targetUrl;
    }

    const scans = await prisma.scan.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: limit,
      include: { findings: { select: { severity: true } } },
    });

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
      const prev = sameTarget[idx + 1];
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

// GET /api/analyzer/scan/:id — user-isolated scan detail
historyRouter.get('/scan/:id', async (req: Request, res: Response) => {
  try {
    const scan = await prisma.scan.findUnique({
      where: { id: req.params.id },
      include: { findings: true },
    });
    if (!scan) return res.status(404).json({ success: false, error: 'Scan not found.' });

    if (isAdmin(req)) {
      return res.json({ success: true, scan });
    }

    const userEmail = req.query.userEmail as string | undefined;
    const userId = req.query.userId as string | undefined;

    if (!scan.userEmail && !scan.userId) {
      return res.status(403).json({ success: false, error: 'Access denied.' });
    }

    const ownerMatch =
      (userEmail && scan.userEmail === userEmail) ||
      (userId && scan.userId === userId);

    if (!ownerMatch) {
      return res.status(403).json({ success: false, error: 'Access denied — this scan belongs to another user.' });
    }

    res.json({ success: true, scan });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// DELETE /api/analyzer/history — admin-only
historyRouter.delete('/history', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    const findingsDeleted = await prisma.finding.deleteMany({});
    const scansDeleted = await prisma.scan.deleteMany({});
    res.json({ success: true, deleted: scansDeleted.count, findingsDeleted: findingsDeleted.count });
  } catch (err: any) {
    console.error('❌ HISTORY CLEAR FAILED:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/analyzer/activity — admin-only
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
        id: true, targetUrl: true, scanType: true, status: true,
        securityScore: true, createdAt: true, userId: true, userEmail: true,
        userName: true, ipAddress: true, userAgent: true, city: true, country: true,
      },
    });
    res.json({ success: true, count: scans.length, activity: scans });
  } catch (err: any) {
    console.error('❌ ACTIVITY FETCH FAILED:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/analyzer/users — admin-only
historyRouter.get('/users', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    const scans = await prisma.scan.findMany({
      where: { userEmail: { not: null } },
      select: { userId: true, userEmail: true, userName: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    });
    const byEmail: Record<string, any> = {};
    for (const s of scans) {
      const email = s.userEmail!;
      if (!byEmail[email]) {
        byEmail[email] = { userId: s.userId, userEmail: email, userName: s.userName, scanCount: 0, lastSeen: s.createdAt };
      }
      byEmail[email].scanCount += 1;
    }
    const bannedUsers = await prisma.user.findMany({ where: { isBanned: true } });
    const bannedByEmail: Record<string, any> = {};
    for (const u of bannedUsers) {
      bannedByEmail[u.email] = { banReason: u.banReason, bannedAt: u.bannedAt };
    }
    const users = Object.values(byEmail).map((u: any) => ({
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

// POST /api/analyzer/users/ban — admin-only
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

// POST /api/analyzer/users/unban — admin-only
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

// GET /api/analyzer/dashboard-stats?userEmail=X — real-time dashboard stats
// User-isolated: without userEmail/userId, returns zeros (privacy default).
// Admins get platform-wide totals automatically.
historyRouter.get('/dashboard-stats', async (req: Request, res: Response) => {
  try {
    const userEmail = req.query.userEmail as string | undefined;
    const userId = req.query.userId as string | undefined;
    const admin = isAdmin(req);

    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);

    let scanWhere: any = { createdAt: { gte: todayStart } };
    let allScanWhere: any = {};
    let aiWhere: any = { createdAt: { gte: todayStart } };

    if (!admin) {
      if (userEmail) {
        scanWhere.userEmail = userEmail;
        allScanWhere.userEmail = userEmail;
        aiWhere.userEmail = userEmail;
      } else if (userId) {
        scanWhere.userId = userId;
        allScanWhere.userId = userId;
        aiWhere.userId = userId;
      } else {
        return res.json({
          success: true,
          modulesActive: 8,
          scansToday: 0,
          threatsFound: 0,
          aiQueriesToday: 0,
        });
      }
    }

    // aiQuery table may not exist yet in older DBs — degrade gracefully instead of 500ing
    const [scansToday, allScans, aiQueriesToday] = await Promise.all([
      prisma.scan.count({ where: scanWhere }),
      prisma.scan.findMany({
        where: allScanWhere,
        select: { findings: { select: { severity: true } } },
      }),
      prisma.aiQuery.count({ where: aiWhere }).catch(() => 0),
    ]);

    const threatsFound = allScans.reduce(
      (sum, s) => sum + s.findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH').length,
      0
    );

    res.json({
      success: true,
      modulesActive: 8,
      scansToday,
      threatsFound,
      aiQueriesToday,
    });
  } catch (err: any) {
    console.error('❌ DASHBOARD STATS FAILED:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});
