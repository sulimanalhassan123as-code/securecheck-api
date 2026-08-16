import { Router, Request, Response } from 'express';
import { prisma } from '../../config/db';
import crypto from 'crypto';

export const telegramConfigRouter = Router();

const ADMIN_KEY = process.env.ADMIN_KEY || '';
const UNLOCK_HOURS = 24;

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

// ─── Helper: get Telegram config from DB or env ───
export async function getTelegramConfig(): Promise<{ botToken: string; chatId: string }> {
  try {
    const rows = await prisma.$queryRawUnsafe(
      `SELECT "botToken", "chatId" FROM "TelegramConfig" WHERE id = 'default' LIMIT 1`
    ) as any[];
    if (rows.length > 0) {
      return {
        botToken: rows[0].botToken || process.env.TELEGRAM_BOT_TOKEN || '',
        chatId: rows[0].chatId || process.env.TELEGRAM_CHAT_ID || '',
      };
    }
  } catch (e) {
    // Table might not exist yet — fall back to env
  }
  return {
    botToken: process.env.TELEGRAM_BOT_TOKEN || '',
    chatId: process.env.TELEGRAM_CHAT_ID || '',
  };
}

// ─── Telegram API helpers ───

async function answerCallbackQuery(botToken: string, callbackQueryId: string, text: string) {
  try {
    await fetch(`https://api.telegram.org/bot${botToken}/answerCallbackQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ callback_query_id: callbackQueryId, text, show_alert: true })
    });
  } catch (e) {
    console.error('answerCallbackQuery error:', (e as Error).message);
  }
}

async function editTelegramMessage(botToken: string, chatId: string, messageId: number, text: string) {
  try {
    await fetch(`https://api.telegram.org/bot${botToken}/editMessageText`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        message_id: messageId,
        text,
        parse_mode: 'HTML',
      }),
    });
  } catch (e) {
    console.error('editMessageText error:', (e as Error).message);
  }
}

// ─── Handle Telegram Callback Query (Approve/Reject button press) ───

async function handleTelegramCallback(update: any): Promise<boolean> {
  const callbackQuery = update.callback_query;
  if (!callbackQuery) return false;

  const data: string = callbackQuery.data || '';
  const { botToken, chatId } = await getTelegramConfig();
  if (!botToken) return false;

  const callbackId = callbackQuery.id;
  const message = callbackQuery.message;
  const messageId = message?.message_id;
  const messageChatId = String(message?.chat?.id || chatId);

  // Parse: "approve:<paymentId>" or "reject:<paymentId>"
  const [action, paymentId] = data.split(':');
  if (!paymentId || (action !== 'approve' && action !== 'reject')) {
    await answerCallbackQuery(botToken, callbackId, 'Unknown action');
    return true;
  }

  try {
    const payment = await prisma.securecheckPayment.findUnique({ where: { id: paymentId } });
    if (!payment) {
      await answerCallbackQuery(botToken, callbackId, '❌ Payment not found');
      return true;
    }

    if (payment.status !== 'pending_review') {
      await answerCallbackQuery(botToken, callbackId, `⚠️ Already ${payment.status}`);
      return true;
    }

    if (action === 'approve') {
      const now = new Date();
      const until = new Date(now.getTime() + UNLOCK_HOURS * 60 * 60 * 1000);

      await prisma.securecheckPayment.update({
        where: { id: paymentId },
        data: { status: 'approved', unlockedAt: now, unlockedUntil: until },
      });

      await answerCallbackQuery(botToken, callbackId, '✅ Payment approved! Device unlocked for 24h.');

      const approvedText =
        `✅ <b>Payment APPROVED</b>\n\n` +
        `<b>Reference:</b> ${payment.reference}\n` +
        `<b>MoMo Tx:</b> ${payment.momoTransactionId}\n` +
        `<b>Phone:</b> ${payment.phoneUsed || 'N/A'}\n` +
        `<b>Device:</b> ${payment.deviceId.substring(0, 16)}...\n` +
        `<b>Unlocked until:</b> ${until.toISOString().split('T')[0]} ${until.toTimeString().split(' ')[0]}`;

      await editTelegramMessage(botToken, messageChatId, messageId, approvedText);

    } else if (action === 'reject') {
      await prisma.securecheckPayment.update({
        where: { id: paymentId },
        data: { status: 'rejected' },
      });

      await answerCallbackQuery(botToken, callbackId, '❌ Payment rejected.');

      const rejectedText =
        `❌ <b>Payment REJECTED</b>\n\n` +
        `<b>Reference:</b> ${payment.reference}\n` +
        `<b>MoMo Tx:</b> ${payment.momoTransactionId}\n` +
        `<b>Phone:</b> ${payment.phoneUsed || 'N/A'}\n` +
        `<b>Device:</b> ${payment.deviceId.substring(0, 16)}...`;

      await editTelegramMessage(botToken, messageChatId, messageId, rejectedText);
    }

    return true;
  } catch (err: any) {
    console.error('Callback handling error:', err.message);
    await answerCallbackQuery(botToken, callbackId, '⚠️ Server error — try the admin panel');
    return true;
  }
}

// ─── Config endpoints ───

telegramConfigRouter.post('/config', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const { botToken, chatId } = req.body;

    const existing = await prisma.$queryRawUnsafe(`SELECT id FROM "TelegramConfig" WHERE id = 'default' LIMIT 1`) as any[];
    if (existing.length > 0) {
      await prisma.$executeRawUnsafe(
        `UPDATE "TelegramConfig" SET "botToken" = $1, "chatId" = $2, "updatedAt" = NOW() WHERE id = 'default'`,
        botToken || null, chatId || null
      );
    } else {
      await prisma.$executeRawUnsafe(
        `INSERT INTO "TelegramConfig" (id, "botToken", "chatId", "createdAt", "updatedAt") VALUES ('default', $1, $2, NOW(), NOW())`,
        botToken || null, chatId || null
      );
    }
    res.json({ success: true, message: 'Telegram config saved.' });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

telegramConfigRouter.get('/config', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const rows = await prisma.$queryRawUnsafe(`SELECT "botToken", "chatId" FROM "TelegramConfig" WHERE id = 'default' LIMIT 1`) as any[];
    res.json({ success: true, config: rows[0] || { botToken: null, chatId: null } });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Webhook: handles both messages and callback queries ───

telegramConfigRouter.post('/webhook', async (req: Request, res: Response) => {
  try {
    const update = req.body;

    // Handle callback_query (inline button press: Approve/Reject)
    if (update.callback_query) {
      const handled = await handleTelegramCallback(update);
      if (handled) return res.json({ success: true });
    }

    // Handle regular message (auto-capture chat ID + bot token)
    const msg = update.message;
    const text = (msg?.text || '').trim();
    const queryToken = (req.query.bt as string) || '';

    // ─── Bot commands ───
    if (msg?.chat?.id && text.startsWith('/')) {
      const chatId = String(msg.chat.id);
      const { botToken } = await getTelegramConfig();
      const bt = botToken || process.env.TELEGRAM_BOT_TOKEN || '';
      if (!bt) return res.json({ success: true });

      async function reply(text: string) {
        await fetch(`https://api.telegram.org/bot${bt}/sendMessage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' })
        });
      }

      // /status — entire bot status: all connections
      if (text === '/status' || text === '/status@gentle_islamic_reminder_bot') {
        const checks: string[] = [];

        // 1. API (Render) — we're running, so it's alive
        checks.push('🟢 SecureCheck API: <b>Online</b>');

        // 2. Database (Supabase)
        try {
          await prisma.$queryRawUnsafe('SELECT 1');
          checks.push('🟢 Database (Supabase): <b>Connected</b>');
        } catch {
          checks.push('🔴 Database (Supabase): <b>Disconnected</b>');
        }

        // 3. Frontend (Vercel)
        try {
          const uiRes = await fetch('https://securecheck-ui.vercel.app/', { signal: AbortSignal.timeout(5000) });
          checks.push(uiRes.ok ? '🟢 Website (Vercel): <b>Online</b>' : '🟡 Website (Vercel): <b>Degraded</b>');
        } catch {
          checks.push('🔴 Website (Vercel): <b>Offline</b>');
        }

        // 4. WhatsApp Bridge (Render)
        try {
          const waRes = await fetch('https://whatsapp-bridge-6bdj.onrender.com/', { signal: AbortSignal.timeout(8000) });
          const waData = await waRes.json() as any;
          const waStatus = waData.whatsapp === 'connected' ? '🟢 WhatsApp: <b>✅ Connected</b>' : '🔴 WhatsApp: <b>❌ Disconnected</b>';
          const groupName = waData.group || 'Not joined';
          checks.push(waStatus + '\nGroup: ' + groupName);
        } catch {
          checks.push('🔴 WhatsApp Bridge: <b>Offline</b>');
        }

        // 5. Telegram bot
        checks.push('🟢 Telegram Bot: <b>Active</b>');

        await reply('📊 <b>SecureCheck Status</b>\n\n' + checks.join('\n'));
        return res.json({ success: true });
      }

      // /wastatus — WhatsApp connection badge only
      if (text === '/wastatus' || text === '/wastatus@gentle_islamic_reminder_bot') {
        try {
          const waRes = await fetch('https://whatsapp-bridge-6bdj.onrender.com/', { signal: AbortSignal.timeout(8000) });
          const waData = await waRes.json() as any;
          if (waData.whatsapp === 'connected') {
            await reply('WhatsApp: ✅ <b>Connected</b>\nGroup: ' + (waData.group || 'Not joined'));
          } else {
            await reply('WhatsApp: ❌ <b>Disconnected</b>');
          }
        } catch {
          await reply('WhatsApp: ❌ <b>Bridge Offline</b>');
        }
        return res.json({ success: true });
      }

      // /start, /help
      if (text === '/start' || text === '/help' || text === '/start@gentle_islamic_reminder_bot' || text === '/help@gentle_islamic_reminder_bot') {
        await reply(
          '🤖 <b>SecureCheck Bot</b>\n\n' +
          'Commands:\n' +
          '/status — Full system status (API, DB, Website, WhatsApp)\n' +
          '/wastatus — WhatsApp connection badge only\n' +
          '/start — Show this help\n\n' +
          'You also receive payment notifications with Approve/Reject buttons here.'
        );
        return res.json({ success: true });
      }

      // Unknown command
      if (text.startsWith('/')) {
        await reply('Unknown command. Send /help for available commands.');
        return res.json({ success: true });
      }
    }


    if (queryToken) {
      const existing = await prisma.$queryRawUnsafe(`SELECT id FROM "TelegramConfig" WHERE id = 'default' LIMIT 1`) as any[];
      if (existing.length > 0) {
        await prisma.$executeRawUnsafe(
          `UPDATE "TelegramConfig" SET "botToken" = $1, "updatedAt" = NOW() WHERE id = 'default'`,
          queryToken
        );
      } else {
        await prisma.$executeRawUnsafe(
          `INSERT INTO "TelegramConfig" (id, "botToken", "createdAt", "updatedAt") VALUES ('default', $1, NOW(), NOW())`,
          queryToken
        );
      }
    }

    if (msg?.chat?.id) {
      const chatId = String(msg.chat.id);
      console.log(`📱 Telegram webhook captured chat ID: ${chatId}`);

      const existing = await prisma.$queryRawUnsafe(`SELECT id, "botToken" FROM "TelegramConfig" WHERE id = 'default' LIMIT 1`) as any[];
      if (existing.length > 0) {
        await prisma.$executeRawUnsafe(
          `UPDATE "TelegramConfig" SET "chatId" = $1, "updatedAt" = NOW() WHERE id = 'default'`,
          chatId
        );
      } else {
        await prisma.$executeRawUnsafe(
          `INSERT INTO "TelegramConfig" (id, "chatId", "createdAt", "updatedAt") VALUES ('default', $1, NOW(), NOW())`,
          chatId
        );
      }

      const configRows = await prisma.$queryRawUnsafe(`SELECT "botToken" FROM "TelegramConfig" WHERE id = 'default' LIMIT 1`) as any[];
      const botToken = configRows[0]?.botToken || process.env.TELEGRAM_BOT_TOKEN;
      if (botToken) {
        await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            chat_id: chatId,
            text: '✅ SecureCheck alerts are now active!\n\nYou will receive payment notifications with Approve/Reject buttons when users submit payments.',
          }),
        });
      }
    }
    res.json({ success: true });
  } catch (err: any) {
    console.error('Telegram webhook error:', err.message);
    res.json({ success: true }); // Always return 200 to Telegram
  }
});

telegramConfigRouter.get('/status', async (req: Request, res: Response) => {
  try {
    const { botToken, chatId } = await getTelegramConfig();
    res.json({
      success: true,
      hasBotToken: !!botToken,
      hasChatId: !!chatId,
      botTokenPreview: botToken ? `${botToken.slice(0, 8)}...` : null,
      chatIdPreview: chatId || null,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

telegramConfigRouter.post('/test', async (req: Request, res: Response) => {
  try {
    const { botToken, chatId } = await getTelegramConfig();
    if (!botToken || !chatId) {
      return res.json({ success: false, error: 'Not configured', hasBotToken: !!botToken, hasChatId: !!chatId });
    }
    const tgRes = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: '🧪 <b>SecureCheck Test Alert</b>\n\nThis confirms your Telegram alert pipeline is working correctly.',
        parse_mode: 'HTML',
      }),
    });
    const tgData = await tgRes.json() as any;
    res.json({ success: tgData.ok === true, telegramResponse: tgData });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});
