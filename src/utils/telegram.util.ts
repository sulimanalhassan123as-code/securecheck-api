/**
 * Telegram Bot notification utility.
 * Sends alerts to a configured chat when critical vulnerabilities are found.
 * Reads config from DB (TelegramConfig table) first, falls back to env vars.
 */
import { getTelegramConfig } from '../modules/telegram/telegram.controller';

export async function sendTelegramMessage(text: string): Promise<boolean> {
  const { botToken, chatId } = await getTelegramConfig();
  if (!botToken || !chatId) {
    console.warn('⚠️ Telegram not configured — skipping alert (set via /api/telegram/config or env vars)');
    return false;
  }
  try {
    const res = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      }),
    });
    const data = await res.json() as any;
    if (!data.ok) {
      console.error('❌ Telegram send failed:', data.description);
      return false;
    }
    return true;
  } catch (err: any) {
    console.error('❌ Telegram error:', err.message);
    return false;
  }
}

/**
 * Sends a formatted alert when a scan finds CRITICAL or HIGH severity vulnerabilities.
 */
export async function alertCriticalFindings(scan: {
  id: string;
  targetUrl?: string | null;
  securityScore: number;
  findings: { title: string; severity: string }[];
  userEmail?: string | null;
  userName?: string | null;
}): Promise<void> {
  const critical = scan.findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');

  if (critical.length === 0) return;

  const severityEmoji: Record<string, string> = {
    CRITICAL: '🔴',
    HIGH: '🟠',
  };

  const lines = critical.slice(0, 10).map(f =>
    `  ${severityEmoji[f.severity] || '⚪'} <b>${f.severity}</b> — ${f.title}`
  ).join('\n');

  const message = `🚨 <b>SecureCheck Alert</b>\n\n` +
    `<b>Target:</b> ${scan.targetUrl || 'Unknown'}\n` +
    `<b>Score:</b> ${scan.securityScore}/100\n` +
    `<b>Issues:</b> ${critical.length} critical/high\n` +
    (scan.userName ? `<b>User:</b> ${scan.userName}\n` : '') +
    (scan.userEmail ? `<b>Email:</b> ${scan.userEmail}\n` : '') +
    `\n<b>Findings:</b>\n${lines}` +
    (critical.length > 10 ? `\n  ...and ${critical.length - 10} more` : '');

  await sendTelegramMessage(message);
}
