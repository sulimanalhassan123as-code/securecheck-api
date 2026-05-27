import { Worker, Job } from 'bullmq';
import { redisConnection } from '../../config/redis';
import { prisma } from '../../config/db';
import { Server } from 'socket.io';

export function initializeScannerWorker(io: Server) {
  return new Worker('web-header-audit-queue', async (job: Job) => {
    const { scanId, targetUrl } = job.data;
    const emitLog = (msg: string, layer = 'NETWORK') => {
      io.emit(`scan-logs:${scanId}`, { message: msg, timestamp: new Date().toISOString(), layer });
    };
    try {
      emitLog(`⚡ Fetching active headers from endpoint: ${targetUrl}...`);
      await prisma.scan.update({ where: { id: scanId }, data: { status: 'PROCESSING' } });
      const startTime = Date.now();
      const response = await fetch(targetUrl, { method: 'HEAD' });
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
          recommendation: "Implement content rules forcing script sources to load from self validation limits.",
          secureCodeExample: "Content-Security-Policy: default-src 'self';"
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
      emitLog('🏁 Target evaluation pipeline completed safely.', 'SYSTEM');
      io.emit(`scan-logs:${scanId}`, { isFinished: true, timestamp: new Date().toISOString() });
    } catch (err: any) {
      await prisma.scan.update({ where: { id: scanId }, data: { status: 'FAILED' } });
      io.emit(`scan-logs:${scanId}`, { isFinished: true, timestamp: new Date().toISOString() });
    }
  }, { connection: redisConnection });
}
