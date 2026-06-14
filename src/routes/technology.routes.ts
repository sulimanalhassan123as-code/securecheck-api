import { Router } from 'express';

const router = Router();

const TECH_SIGNATURES: { name: string; patterns: string[] }[] = [
  { name: 'React',        patterns: ['react', '__react', '_reactRootContainer'] },
  { name: 'Next.js',      patterns: ['__next', '_next/static', 'next/dist'] },
  { name: 'Vue.js',       patterns: ['vue.js', '__vue', 'vuejs'] },
  { name: 'Angular',      patterns: ['ng-version', 'angular.js', 'ng-app'] },
  { name: 'WordPress',    patterns: ['wp-content', 'wp-includes', 'wordpress'] },
  { name: 'Shopify',      patterns: ['shopify', 'cdn.shopify.com'] },
  { name: 'Vercel',       patterns: ['vercel', 'x-vercel-id'] },
  { name: 'Cloudflare',   patterns: ['cloudflare', 'cf-ray', 'cf-cache-status'] },
  { name: 'Nginx',        patterns: ['nginx'] },
  { name: 'Apache',       patterns: ['apache'] },
  { name: 'Node.js',      patterns: ['node.js', 'express'] },
  { name: 'jQuery',       patterns: ['jquery', 'jQuery'] },
  { name: 'Bootstrap',    patterns: ['bootstrap.min.css', 'bootstrap.min.js'] },
  { name: 'Tailwind CSS', patterns: ['tailwind'] },
  { name: 'Google Analytics', patterns: ['google-analytics', 'gtag', 'ga.js'] },
];

router.post('/', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, error: 'URL required' });

    let html = '';
    let responseHeaders: Record<string, string> = {};

    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(10000) });
      html = await r.text();
      r.headers.forEach((v, k) => { responseHeaders[k] = v; });
    } catch (e) {
      return res.status(500).json({ success: false, error: 'Could not fetch target URL' });
    }

    const combined = (html + JSON.stringify(responseHeaders)).toLowerCase();
    const detected: string[] = [];

    for (const tech of TECH_SIGNATURES) {
      if (tech.patterns.some(p => combined.includes(p.toLowerCase()))) {
        detected.push(tech.name);
      }
    }

    const score = Math.min(100, 60 + detected.length * 5);

    const findings = detected.map(t => ({ title: 'Detected', value: t }));

    res.json({
      success: true,
      target: url,
      score,
      technologies: detected.length > 0 ? detected : ['Unknown stack'],
      findings,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Technology scan failed' });
  }
});

export default router;
