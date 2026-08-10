import { Router, Request, Response } from 'express';
import { prisma } from '../../config/db';
import crypto from 'crypto';

const router = Router();

const ADMIN_KEY = process.env.ADMIN_KEY || '';
const MOMO_NUMBER = '0599931348';
const MOMO_AMOUNT = 10;
const FREE_DAILY_LIMIT = 1;
const UNLOCK_HOURS = 24;

// ─── Quota ───

router.post('/check_quota', async (req: Request, res: Response) => {
  try {
    const { deviceId } = req.body;
    if (!deviceId) return res.status(400).json({ error: 'deviceId required' });

    const today = new Date().toISOString().split('T')[0];
    let quota = await prisma.securecheckQuota.findUnique({
      where: { deviceId_date: { deviceId, date: today } }
    });

    if (!quota) {
      quota = await prisma.securecheckQuota.create({
        data: { deviceId, date: today, usedToday: 0, freeLimit: FREE_DAILY_LIMIT }
      });
    }

    res.json({ usedToday: quota.usedToday, freeLimit: quota.freeLimit, canScan: quota.usedToday < quota.freeLimit });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/increment_quota', async (req: Request, res: Response) => {
  try {
    const { deviceId } = req.body;
    if (!deviceId) return res.status(400).json({ error: 'deviceId required' });

    const today = new Date().toISOString().split('T')[0];
    let quota = await prisma.securecheckQuota.findUnique({
      where: { deviceId_date: { deviceId, date: today } }
    });

    if (quota) {
      quota = await prisma.securecheckQuota.update({
        where: { id: quota.id },
        data: { usedToday: { increment: 1 } }
      });
    } else {
      quota = await prisma.securecheckQuota.create({
        data: { deviceId, date: today, usedToday: 1, freeLimit: FREE_DAILY_LIMIT }
      });
    }

    res.json({ ok: true, incremented: true, usedToday: quota.usedToday });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Unlock Check ───

router.post('/check_unlock', async (req: Request, res: Response) => {
  try {
    const { deviceId } = req.body;
    if (!deviceId) return res.status(400).json({ error: 'deviceId required' });

    const now = new Date();
    const approved = await prisma.securecheckPayment.findFirst({
      where: {
        deviceId,
        status: 'approved',
        unlockedUntil: { gt: now }
      },
      orderBy: { unlockedUntil: 'desc' }
    });

    if (approved) {
      res.json({ unlocked: true, until: approved.unlockedUntil?.toISOString() });
    } else {
      res.json({ unlocked: false });
    }
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Payment Flow ───

function generateReference(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let ref = 'SC-';
  for (let i = 0; i < 6; i++) {
    ref += chars[Math.floor(Math.random() * chars.length)];
  }
  return ref;
}

router.post('/initiate_payment', async (req: Request, res: Response) => {
  try {
    const { deviceId } = req.body;
    if (!deviceId) return res.status(400).json({ error: 'deviceId required' });

    const reference = generateReference();

    await prisma.securecheckPayment.create({
      data: {
        deviceId,
        reference,
        amount: MOMO_AMOUNT,
        momoNumber: MOMO_NUMBER,
        status: 'pending_review',
      }
    });

    res.json({
      reference,
      momoNumber: MOMO_NUMBER,
      amount: MOMO_AMOUNT,
      instructions: `Send GHS ${MOMO_AMOUNT} via MoMo to ${MOMO_NUMBER}, then submit your reference (${reference}) and the MoMo transaction ID.`
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/confirm_payment', async (req: Request, res: Response) => {
  try {
    const { deviceId, reference, momoTransactionId, phoneUsed } = req.body;
    if (!deviceId || !reference) return res.status(400).json({ error: 'deviceId and reference required' });
    if (!momoTransactionId) return res.status(400).json({ error: 'MoMo transaction ID required' });

    const payment = await prisma.securecheckPayment.findFirst({
      where: { deviceId, reference, status: 'pending_review' }
    });

    if (!payment) {
      return res.status(404).json({ error: 'No pending payment found for this reference' });
    }

    await prisma.securecheckPayment.update({
      where: { id: payment.id },
      data: { momoTransactionId, phoneUsed: phoneUsed || '' }
    });

    res.json({ ok: true, status: 'pending_review' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin: verify key ───

function verifyAdmin(req: Request): boolean {
  const key = req.body.adminKey || req.header('x-admin-key');
  if (!ADMIN_KEY || key !== ADMIN_KEY) return false;
  return true;
}

router.post('/admin_list_payments', async (req: Request, res: Response) => {
  if (!verifyAdmin(req)) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const { status } = req.body;
    const where = status ? { status } : {};
    const payments = await prisma.securecheckPayment.findMany({
      where,
      orderBy: { createdAt: 'desc' }
    });

    res.json({
      ok: true,
      payments: payments.map(p => ({
        id: p.id,
        deviceId: p.deviceId,
        reference: p.reference,
        amount: p.amount,
        momoNumber: p.momoNumber,
        momoTransactionId: p.momoTransactionId,
        phoneUsed: p.phoneUsed,
        status: p.status,
        createdAt: p.createdAt.toISOString(),
        unlockedUntil: p.unlockedUntil?.toISOString() || null
      }))
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/admin_approve_payment', async (req: Request, res: Response) => {
  if (!verifyAdmin(req)) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const { paymentId } = req.body;
    if (!paymentId) return res.status(400).json({ error: 'paymentId required' });

    const now = new Date();
    const until = new Date(now.getTime() + UNLOCK_HOURS * 60 * 60 * 1000);

    await prisma.securecheckPayment.update({
      where: { id: paymentId },
      data: {
        status: 'approved',
        unlockedAt: now,
        unlockedUntil: until
      }
    });

    res.json({ ok: true, unlocked: true, until: until.toISOString() });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/admin_reject_payment', async (req: Request, res: Response) => {
  if (!verifyAdmin(req)) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const { paymentId } = req.body;
    if (!paymentId) return res.status(400).json({ error: 'paymentId required' });

    await prisma.securecheckPayment.update({
      where: { id: paymentId },
      data: { status: 'rejected' }
    });

    res.json({ ok: true, rejected: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export const gateRouter = router;
