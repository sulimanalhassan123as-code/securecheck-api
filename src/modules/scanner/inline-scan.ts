import { prisma } from '../../config/db';
import { alertCriticalFindings } from '../../utils/telegram.util';

/**
 * Shared inline scan logic — used when Redis/BullMQ is not available.
 * Performs HTTP header security analysis directly and saves results to DB.
 * Also sends Telegram alerts when CRITICAL/HIGH findings are detected.
 */
export async function runInlineScan(scanId: string, targetUrl: string) {
  try {
    await prisma.scan.update({ where: { id: scanId }, data: { status: 'PROCESSING' } });
    const startTime = Date.now();
    const response = await fetch(targetUrl, { method: 'HEAD', signal: AbortSignal.timeout(15000) });
    const headers = response.headers;
    const duration = Date.now() - startTime;
    let score = 100;
    let findingsList: any[] = [];

    if (!headers.get('Strict-Transport-Security')) {
      score -= 20;
      findingsList.push({
        title: 'Missing HSTS Security Shielding Policy',
        severity: 'HIGH',
        description: 'Strict-Transport-Security header was not detected.',
        riskExplanation: 'Allows attackers to downgrade network handshakes to unencrypted HTTP protocols.',
        attackScenario: "Potential attacker exploitation path detected during automated audit.",
        recommendation: 'Configure your server production runtime to inject: Strict-Transport-Security: max-age=31536000;',
        secureCodeExample: 'Strict-Transport-Security: max-age=31536000;'
      });
    }
    if (!headers.get('Content-Security-Policy')) {
      score -= 25;
      findingsList.push({
        title: 'Missing Content-Security-Policy (CSP)',
        severity: 'CRITICAL',
        description: 'Content-Security-Policy header is missing on your endpoint.',
        riskExplanation: 'Exposes application vectors to Cross-Site Scripting (XSS) script injections.',
        attackScenario: "Potential attacker exploitation path detected during automated audit.",
        recommendation: "Implement content rules forcing script sources to load from self validation limits.",
        secureCodeExample: "Content-Security-Policy: default-src 'self';"
      });
    }
    if (!headers.get('X-Frame-Options')) {
      score -= 15;
      findingsList.push({
        title: 'Missing X-Frame-Options',
        severity: 'MEDIUM',
        description: 'X-Frame-Options header is missing.',
        riskExplanation: 'Application may be vulnerable to clickjacking attacks.',
        attackScenario: "Attacker embeds your page in an iframe to trick users into clicking.",
        recommendation: 'Add: X-Frame-Options: DENY',
        secureCodeExample: 'X-Frame-Options: DENY'
      });
    }
    if (!headers.get('X-Content-Type-Options')) {
      score -= 10;
      findingsList.push({
        title: 'Missing X-Content-Type-Options',
        severity: 'LOW',
        description: 'X-Content-Type-Options header is missing.',
        riskExplanation: 'Browser may MIME-sniff content and execute unexpected file types.',
        attackScenario: "Attacker uploads a file that gets interpreted as a different type.",
        recommendation: 'Add: X-Content-Type-Options: nosniff',
        secureCodeExample: 'X-Content-Type-Options: nosniff'
      });
    }
    if (!headers.get('Referrer-Policy')) {
      score -= 5;
      findingsList.push({
        title: 'Missing Referrer-Policy',
        severity: 'LOW',
        description: 'Referrer-Policy header is missing.',
        riskExplanation: 'Referrer information may leak to external sites.',
        attackScenario: "Sensitive URL parameters could be exposed via Referer header.",
        recommendation: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
        secureCodeExample: 'Referrer-Policy: strict-origin-when-cross-origin'
      });
    }

    await prisma.$transaction(async (tx) => {
      if (findingsList.length > 0) {
        await tx.finding.createMany({ data: findingsList.map(f => ({ ...f, scanId })) });
      }
      await tx.scan.update({
        where: { id: scanId },
        data: { status: 'COMPLETED', securityScore: Math.max(0, score), durationMs: duration }
      });
    });

    // Send Telegram alert if CRITICAL or HIGH findings were found
    try {
      const scanRecord = await prisma.scan.findUnique({
        where: { id: scanId },
        select: { targetUrl: true, securityScore: true, userName: true, userEmail: true },
      });
      if (scanRecord && findingsList.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')) {
        await alertCriticalFindings({
          id: scanId,
          targetUrl: scanRecord.targetUrl,
          securityScore: scanRecord.securityScore,
          findings: findingsList.map(f => ({ title: f.title, severity: f.severity })),
          userEmail: scanRecord.userEmail,
          userName: scanRecord.userName,
        });
      }
    } catch (e: any) {
      console.error('⚠️ Telegram alert failed:', e.message);
    }

    return { success: true, score: Math.max(0, score), findings: findingsList.length, duration };
  } catch (err: any) {
    await prisma.scan.update({ where: { id: scanId }, data: { status: 'FAILED' } });
    return { success: false, error: err.message };
  }
}
