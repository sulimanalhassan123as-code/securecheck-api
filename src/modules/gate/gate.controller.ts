import { Router, Request, Response } from 'express';
import { prisma } from '../../config/db';
import { getTelegramConfig } from '../telegram/telegram.controller';
import crypto from 'crypto';

const router = Router();

const ADMIN_KEY = process.env.ADMIN_KEY || '';
const MOMO_NUMBER = '0599931348';
const MOMO_AMOUNT = 10;
const FREE_DAILY_LIMIT = 1;
const UNLOCK_HOURS = 24;

// ─── Telegram Notification Helper ───

async function sendTelegramAlert(text: string) {
  try {
    const { botToken, chatId } = await getTelegramConfig();
    if (!botToken || !chatId) return;
    await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' })
    });
  } catch (e) {
    console.error('Telegram alert error:', (e as Error).message);
  }
}

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

/**
 * Step 1: Generate payment reference and show instructions.
 * Does NOT create a database record — the record is only created
 * when the user actually submits their MoMo transaction ID (Step 2).
 * This prevents empty payments from showing in the admin panel.
 */
router.post('/initiate_payment', async (req: Request, res: Response) => {
  try {
    const { deviceId } = req.body;
    if (!deviceId) return res.status(400).json({ error: 'deviceId required' });

    const reference = generateReference();

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

/**
 * Step 2: User submits their MoMo transaction ID.
 * THIS is where the database record is created and the admin is notified.
 * Admin only sees payments where the user has actually submitted proof.
 */
router.post('/confirm_payment', async (req: Request, res: Response) => {
  try {
    const { deviceId, reference, momoTransactionId, phoneUsed } = req.body;
    if (!deviceId || !reference) return res.status(400).json({ error: 'deviceId and reference required' });
    if (!momoTransactionId) return res.status(400).json({ error: 'MoMo transaction ID required' });

    // Check if this reference was already submitted (prevent duplicates)
    const existing = await prisma.securecheckPayment.findFirst({
      where: { deviceId, reference }
    });

    if (existing) {
      // Already submitted — return current status
      return res.json({ ok: true, status: existing.status, alreadySubmitted: true });
    }

    // Create the payment record NOW (only when user has submitted proof)
    const payment = await prisma.securecheckPayment.create({
      data: {
        deviceId,
        reference,
        amount: MOMO_AMOUNT,
        momoNumber: MOMO_NUMBER,
        momoTransactionId,
        phoneUsed: phoneUsed || '',
        status: 'pending_review',
      }
    });

    // ─── Send instant Telegram notification to admin ───
    const timestamp = new Date().toLocaleString('en-GB', { timeZone: 'Africa/Accra' });
    await sendTelegramAlert(
      `🔔 <b>New SecureCheck Payment</b>\n\n` +
      `<b>Reference:</b> ${reference}\n` +
      `<b>Amount:</b> GHS ${MOMO_AMOUNT}\n` +
      `<b>MoMo Tx ID:</b> ${momoTransactionId}\n` +
      `<b>Phone:</b> ${phoneUsed || 'Not provided'}\n` +
      `<b>Device:</b> ${deviceId.substring(0, 16)}...\n` +
      `<b>Time:</b> ${timestamp}\n\n` +
      `👉 Review and approve on the admin panel.`
    );

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
      payments: payments.map((p: any) => ({
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

    const payment = await prisma.securecheckPayment.update({
      where: { id: paymentId },
      data: {
        status: 'approved',
        unlockedAt: now,
        unlockedUntil: until
      }
    });

    // ─── Send Telegram confirmation ───
    await sendTelegramAlert(
      `✅ <b>Payment Approved</b>\n\n` +
      `<b>Reference:</b> ${payment.reference}\n` +
      `<b>MoMo Tx:</b> ${payment.momoTransactionId}\n` +
      `<b>Device:</b> ${payment.deviceId.substring(0, 16)}...\n` +
      `<b>Unlocked until:</b> ${until.toISOString()}\n\n` +
      `Deep scans are now available for this device.`
    );

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

    const payment = await prisma.securecheckPayment.update({
      where: { id: paymentId },
      data: { status: 'rejected' }
    });

    // ─── Send Telegram rejection notice ───
    await sendTelegramAlert(
      `❌ <b>Payment Rejected</b>\n\n` +
      `<b>Reference:</b> ${payment.reference}\n` +
      `<b>MoMo Tx:</b> ${payment.momoTransactionId}\n` +
      `<b>Device:</b> ${payment.deviceId.substring(0, 16)}...`
    );

    res.json({ ok: true, rejected: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export const gateRouter = router;
