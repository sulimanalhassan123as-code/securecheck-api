import { Router, Request, Response } from 'express';
import { prisma } from '../../config/db';
import crypto from 'crypto';

export const telegramConfigRouter = Router();

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

// POST /api/telegram/config — store bot token and chat ID in DB (admin-only)
telegramConfigRouter.post('/config', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const { botToken, chatId } = req.body;

    // Upsert a single config row (id = 'default')
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

// GET /api/telegram/config — read current config (admin-only)
telegramConfigRouter.get('/config', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const rows = await prisma.$queryRawUnsafe(`SELECT "botToken", "chatId" FROM "TelegramConfig" WHERE id = 'default' LIMIT 1`) as any[];
    res.json({ success: true, config: rows[0] || { botToken: null, chatId: null } });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/telegram/webhook — receives Telegram updates, auto-captures chat ID
// The bot token can be passed via ?bt= query param for auto-setup
telegramConfigRouter.post('/webhook', async (req: Request, res: Response) => {
  try {
    const update = req.body;
    const msg = update.message || update.callback_query?.message;

    // Auto-capture bot token from query param if provided (for zero-config setup)
    const queryToken = (req.query.bt as string) || '';
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
      console.log(`📱 Telegram webhook captured chat ID: ${chatId} from @${msg.from?.username || msg.from?.first_name || 'unknown'}`);

      // Store the chat ID in the config table
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

      // Send a confirmation message
      const configRows = await prisma.$queryRawUnsafe(`SELECT "botToken" FROM "TelegramConfig" WHERE id = 'default' LIMIT 1`) as any[];
      const botToken = configRows[0]?.botToken || process.env.TELEGRAM_BOT_TOKEN;
      if (botToken) {
        await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            chat_id: chatId,
            text: '✅ SecureCheck alerts are now active! You will receive notifications when critical vulnerabilities are found.',
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

// Helper: get Telegram config from DB or env
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
