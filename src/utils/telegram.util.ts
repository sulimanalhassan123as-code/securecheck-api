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

/**
 * Sends a formatted alert when a GitHub push event detects code vulnerabilities.
 */
export async function alertCodeFindings(data: {
  repoName: string;
  branch: string;
  pusher: string;
  commitMsg: string;
  filesScanned: number;
  findings: Array<{ file: string; line: number; severity: string; title: string; codeSnippet: string }>;
}): Promise<void> {
  const severityEmoji: Record<string, string> = {
    CRITICAL: '🔴',
    HIGH: '🟠',
    MEDIUM: '🟡',
    LOW: '⚪',
  };

  const lines = data.findings.slice(0, 12).map(f =>
    `  ${severityEmoji[f.severity] || '⚪'} <b>${f.severity}</b> — ${f.title}\n     📄 ${f.file}:${f.line}\n     <code>${f.codeSnippet.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code>`
  ).join('\n');

  const message = `🚨 <b>SecureCheck Code Alert</b>\n\n` +
    `📦 <b>Repo:</b> ${data.repoName}\n` +
    `🌿 <b>Branch:</b> ${data.branch}\n` +
    `👤 <b>Pushed by:</b> ${data.pusher}\n` +
    `💬 <b>Commit:</b> ${data.commitMsg}\n` +
    `📁 <b>Files scanned:</b> ${data.filesScanned}\n` +
    `⚠️ <b>Issues found:</b> ${data.findings.length} critical/high\n\n` +
    `<b>Findings:</b>\n${lines}` +
    (data.findings.length > 12 ? `\n  ...and ${data.findings.length - 12} more` : '');

  await sendTelegramMessage(message);
}


/**
 * Sends a daily consolidated security summary of all GitHub repos.
 */
export async function sendDailySecuritySummary(data: {
  totalRepos: number;
  reposScanned: number;
  reposWithIssues: number;
  totalCritical: number;
  totalHigh: number;
  totalMedium: number;
  topFindings: Array<{ repo: string; severity: string; title: string; file: string }>;
  cleanRepos: number;
}): Promise<void> {
  const severityEmoji: Record<string, string> = {
    CRITICAL: '🔴',
    HIGH: '🟠',
    MEDIUM: '🟡',
  };

  const today = new Date().toLocaleDateString('en-GB', { 
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' 
  });

  let message = `📊 <b>SecureCheck Daily Security Report</b>

` +
    `📅 <b>${today}</b>

` +
    `📦 <b>Repos Monitored:</b> ${data.totalRepos}
` +
    `🔍 <b>Repos Scanned:</b> ${data.reposScanned}
` +
    `✅ <b>Clean Repos:</b> ${data.cleanRepos}
` +
    `⚠️ <b>Repos with Issues:</b> ${data.reposWithIssues}

` +
    `<b>Issue Breakdown:</b>
` +
    `🔴 Critical: ${data.totalCritical}
` +
    `🟠 High: ${data.totalHigh}
` +
    `🟡 Medium: ${data.totalMedium}
`;

  if (data.topFindings.length > 0) {
    message += `
<b>Top Findings (latest commit per repo):</b>
`;
    const findings = data.topFindings.slice(0, 15).map(f =>
      `  ${severityEmoji[f.severity] || '⚪'} ${f.severity} — ${f.title}
     📦 ${f.repo}
     📄 ${f.file}`
    ).join('\n');
    message += findings;
    if (data.topFindings.length > 15) {
      message += `\n  ...and ${data.topFindings.length - 15} more findings`;
    }
  } else {
    message += `
✅ <b>All clear!</b> No critical or high issues found in any repo.`;
  }

  await sendTelegramMessage(message);
}
