/**
 * Telegram Bot notification utility.
 * Sends alerts to a configured chat when critical vulnerabilities are found.
 *
 * Required env vars:
 *   TELEGRAM_BOT_TOKEN  — bot token from @BotFather
 *   TELEGRAM_CHAT_ID     — numeric chat ID to receive alerts
 */
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const CHAT_ID = process.env.TELEGRAM_CHAT_ID || '';

const API_BASE = `https://api.telegram.org/bot${BOT_TOKEN}`;

export async function sendTelegramMessage(text: string): Promise<boolean> {
  if (!BOT_TOKEN || !CHAT_ID) {
    console.warn('⚠️ Telegram not configured — skipping alert (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)');
    return false;
  }
  try {
    const res = await fetch(`${API_BASE}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: CHAT_ID,
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
