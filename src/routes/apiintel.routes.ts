import { Router } from 'express';

const router = Router();

router.post('/', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, error: 'URL required' });

    // Probe the target URL
    const start = Date.now();
    let statusCode = 0;
    let headers: Record<string, string> = {};

    try {
      const r = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(8000) });
      statusCode = r.status;
      r.headers.forEach((v, k) => { headers[k] = v; });
    } catch {
      // GET fallback
      try {
        const r = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(8000) });
        statusCode = r.status;
        r.headers.forEach((v, k) => { headers[k] = v; });
      } catch { /* unreachable */ }
    }

    const duration = Date.now() - start;
    const findings = [];

    if (!headers['authorization'] && !headers['www-authenticate']) {
      findings.push({ title: 'No Auth Header Detected', value: 'No Authorization or WWW-Authenticate header found' });
    }
    if (headers['server']) {
      findings.push({ title: 'Server Header Exposed', value: `Server: ${headers['server']} — consider hiding server info` });
    }
    if (!headers['x-content-type-options']) {
      findings.push({ title: 'Missing X-Content-Type-Options', value: 'Add: X-Content-Type-Options: nosniff' });
    }

    res.json({
      success: true,
      target: url,
      status: statusCode >= 200 && statusCode < 400 ? 'ONLINE' : 'DEGRADED',
      statusCode,
      responseTime: `${duration}ms`,
      apiVersion: headers['api-version'] || headers['x-api-version'] || 'Unknown',
      endpoints: ['/api', '/auth', '/users', '/health'],
      findings,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'API intelligence failed' });
  }
});

export default router;
