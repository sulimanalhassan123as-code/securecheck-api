import { Router, Request, Response } from 'express';
import { prisma } from '../../config/db';
import { getTelegramConfig } from '../telegram/telegram.controller';
import crypto from 'crypto';

const router = Router();

// ─── Diagnostic: track confirm_payment calls ───
const confirmCallLog: any[] = [];


const ADMIN_KEY = process.env.ADMIN_KEY || '';
const MOMO_NUMBER = '0599931348';
const MOMO_AMOUNT = 10;
const FREE_DAILY_LIMIT = 1;
const UNLOCK_HOURS = 24;

// ─── Telegram Notification with Inline Buttons ───

async function sendTelegramPaymentAlert(payment: { id: string; reference: string; momoTransactionId: string; phoneUsed: string; deviceId: string }): Promise<{ ok: boolean; error?: string }> {
  try {
    const { botToken, chatId } = await getTelegramConfig();
    if (!botToken || !chatId) {
      console.error('[Telegram] No bot token or chat ID configured');
      return { ok: false, error: 'No bot token or chat ID' };
    }

    const timestamp = new Date().toLocaleString('en-GB', { timeZone: 'Africa/Accra' });
    const shortDevice = payment.deviceId.substring(0, 16);

    const text =
      `🔔 <b>New SecureCheck Payment</b>\n\n` +
      `<b>Reference:</b> ${payment.reference}\n` +
      `<b>Amount:</b> GHS ${MOMO_AMOUNT}\n` +
      `<b>MoMo Tx ID:</b> ${payment.momoTransactionId}\n` +
      `<b>Phone:</b> ${payment.phoneUsed || 'Not provided'}\n` +
      `<b>Device:</b> ${shortDevice}...\n` +
      `<b>Time:</b> ${timestamp}\n\n` +
      `Tap a button below to review:`;

    // Inline keyboard with Approve / Reject buttons
    const keyboard = {
      inline_keyboard: [
        [
          { text: '✅ Approve', callback_data: `approve:${payment.id}` },
          { text: '❌ Reject', callback_data: `reject:${payment.id}` },
        ],
      ],
    };

    const tgRes = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'HTML',
        reply_markup: keyboard,
      }),
    });

    const tgData = await tgRes.json() as any;
    if (!tgData.ok) {
      console.error('[Telegram] API error:', JSON.stringify(tgData));
      return { ok: false, error: tgData.description || 'Telegram API error' };
    }
    
    console.log('[Telegram] Notification sent successfully for', payment.reference);
    return { ok: true };
  } catch (e) {
    console.error('[Telegram] alert error:', (e as Error).message);
    return { ok: false, error: (e as Error).message };
  }
}

async function sendTelegramSimpleAlert(text: string) {
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

async function answerCallbackQuery(botToken: string, callbackQueryId: string, text: string) {
  try {
    await fetch(`https://api.telegram.org/bot${botToken}/answerCallbackQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ callback_query_id: callbackQueryId, text, show_alert: false })
    });
  } catch (e) {
    console.error('answerCallbackQuery error:', (e as Error).message);
  }
}

async function editTelegramMessage(botToken: string, chatId: string, messageId: number, text: string, replyMarkup?: any) {
  try {
    await fetch(`https://api.telegram.org/bot${botToken}/editMessageText`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        message_id: messageId,
        text,
        parse_mode: 'HTML',
        ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
      }),
    });
  } catch (e) {
    console.error('editMessageText error:', (e as Error).message);
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

router.post('/confirm_payment', async (req: Request, res: Response) => {
  try {
    const { deviceId, reference, momoTransactionId, phoneUsed } = req.body;
    
    // Diagnostic log
    confirmCallLog.unshift({
      timestamp: new Date().toISOString(),
      deviceId: deviceId || 'MISSING',
      reference: reference || 'MISSING',
      momoTransactionId: momoTransactionId || 'MISSING',
      phoneUsed: phoneUsed || 'MISSING',
      origin: req.headers.origin || req.headers.referer || 'none',
      ip: req.ip || req.socket.remoteAddress || 'unknown',
    });
    if (confirmCallLog.length > 20) confirmCallLog.pop();
    console.log('[confirm_payment] Request:', { deviceId, reference, momoTransactionId, origin: req.headers.origin });
    
    if (!deviceId || !reference) return res.status(400).json({ error: 'deviceId and reference required' });
    if (!momoTransactionId) return res.status(400).json({ error: 'MoMo transaction ID required' });

    // Check if this reference was already submitted
    const existing = await prisma.securecheckPayment.findFirst({
      where: { deviceId, reference }
    });

    if (existing) {
      return res.json({ ok: true, status: existing.status, alreadySubmitted: true });
    }

    // Create the payment record
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

    // Send Telegram notification with Approve/Reject buttons
    const tgResult = await sendTelegramPaymentAlert({
      id: payment.id,
      reference: payment.reference,
      momoTransactionId: payment.momoTransactionId,
      phoneUsed: payment.phoneUsed,
      deviceId: payment.deviceId,
    });

    // Log Telegram result in diagnostic
    if (confirmCallLog[0]) {
      confirmCallLog[0].telegramSent = tgResult.ok;
      confirmCallLog[0].telegramError = tgResult.error || null;
    }

    res.json({ ok: true, status: 'pending_review', telegramSent: tgResult.ok });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin endpoints ───

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

    await sendTelegramSimpleAlert(
      `✅ <b>Payment Approved (via admin panel)</b>\n\n` +
      `<b>Reference:</b> ${payment.reference}\n` +
      `<b>MoMo Tx:</b> ${payment.momoTransactionId}\n` +
      `<b>Device:</b> ${payment.deviceId.substring(0, 16)}...\n` +
      `<b>Unlocked until:</b> ${until.toISOString()}`
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

    await sendTelegramSimpleAlert(
      `❌ <b>Payment Rejected (via admin panel)</b>\n\n` +
      `<b>Reference:</b> ${payment.reference}\n` +
      `<b>MoMo Tx:</b> ${payment.momoTransactionId}\n` +
      `<b>Device:</b> ${payment.deviceId.substring(0, 16)}...`
    );

    res.json({ ok: true, rejected: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Diagnostic endpoint ───
router.post('/diagnostic_log', (req: Request, res: Response) => {
  if (!verifyAdmin(req)) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ ok: true, calls: confirmCallLog });
});

export const gateRouter = router;
