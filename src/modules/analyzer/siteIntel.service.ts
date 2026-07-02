// Deep site intelligence: fetches the live page, pulls public assets (JS/CSS),
// scans them for exposed secrets/config, detects the tech stack, and checks headers.

const SECRET_PATTERNS: { label: string; regex: RegExp }[] = [
  { label: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
  { label: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g },
  { label: 'Stripe Live Secret Key', regex: /sk_live_[0-9a-zA-Z]{20,}/g },
  { label: 'Stripe Publishable Key', regex: /pk_live_[0-9a-zA-Z]{20,}/g },
  { label: 'Generic Private Key Block', regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g },
  { label: 'Slack Token', regex: /xox[baprs]-[0-9A-Za-z-]{10,}/g },
  { label: 'JWT-looking Token', regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { label: 'Supabase Service Role Reference', regex: /service_role/gi },
  { label: 'Generic API Key Assignment', regex: /(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*["'][0-9a-zA-Z\-_]{16,}["']/gi },
  { label: 'Hardcoded Password Assignment', regex: /(password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']/gi },
];

const TECH_SIGNATURES: { label: string; test: (html: string) => boolean }[] = [
  { label: 'React', test: (h) => /react/i.test(h) || /__REACT/.test(h) },
  { label: 'Vue.js', test: (h) => /vue(\.js)?/i.test(h) && /data-v-/.test(h) },
  { label: 'Next.js', test: (h) => /__NEXT_DATA__/.test(h) },
  { label: 'Vite Build', test: (h) => /\/assets\/index-[\w-]+\.js/.test(h) },
  { label: 'WordPress', test: (h) => /wp-content|wp-includes/i.test(h) },
  { label: 'Supabase', test: (h) => /supabase\.co/i.test(h) },
  { label: 'Firebase', test: (h) => /firebaseapp\.com|firebaseio\.com/i.test(h) },
  { label: 'Stripe', test: (h) => /js\.stripe\.com/i.test(h) },
  { label: 'Google Analytics', test: (h) => /gtag\(|googletagmanager\.com/i.test(h) },
  { label: 'Cloudflare', test: (h) => /cloudflare/i.test(h) },
  { label: 'Tailwind CSS', test: (h) => /tailwind/i.test(h) },
  { label: 'jQuery', test: (h) => /jquery/i.test(h) },
];

export interface SiteIntelReport {
  targetUrl: string;
  finalUrl: string;
  statusCode: number;
  headers: Record<string, string>;
  missingSecurityHeaders: string[];
  technologies: string[];
  assetsScanned: string[];
  exposedSecrets: { label: string; foundIn: string; sample: string }[];
  pageTitle?: string;
  metaDescription?: string;
  robotsTxt?: string;
  sitemapFound: boolean;
  crawledPageCount: number;
  crawledSummaries: { url: string; title?: string; excerpt?: string }[];
}

function extractAssetUrls(html: string, baseUrl: string): string[] {
  const urls = new Set<string>();
  const patterns = [
    /<script[^>]+src=["']([^"']+)["']/gi,
    /<link[^>]+href=["']([^"']+\.css[^"']*)["']/gi,
  ];
  for (const pattern of patterns) {
    let m;
    while ((m = pattern.exec(html)) !== null) {
      try {
        const abs = new URL(m[1], baseUrl).toString();
        urls.add(abs);
      } catch {
        /* ignore invalid URL */
      }
    }
  }
  return Array.from(urls).slice(0, 12); // cap to avoid excessive requests
}

function scanTextForSecrets(text: string, sourceLabel: string) {
  const found: { label: string; foundIn: string; sample: string }[] = [];
  for (const { label, regex } of SECRET_PATTERNS) {
    const matches = text.match(regex);
    if (matches && matches.length > 0) {
      found.push({ label, foundIn: sourceLabel, sample: matches[0].slice(0, 60) });
    }
  }
  return found;
}

export async function buildSiteIntelReport(targetUrl: string, crawledPages: { url: string; text?: string; html?: string; title?: string }[]): Promise<SiteIntelReport> {
  const mainResp = await fetch(targetUrl, { redirect: 'follow' });
  const finalUrl = mainResp.url || targetUrl;
  const html = await mainResp.text();
  const headers: Record<string, string> = {};
  mainResp.headers.forEach((v, k) => (headers[k] = v));

  const requiredHeaders = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
  ];
  const missingSecurityHeaders = requiredHeaders.filter((h) => !headers[h]);

  const technologies = TECH_SIGNATURES.filter((t) => t.test(html)).map((t) => t.label);

  const assetUrls = extractAssetUrls(html, finalUrl);
  const exposedSecrets = [...scanTextForSecrets(html, 'Main HTML')];
  const assetsScanned: string[] = [];

  for (const assetUrl of assetUrls) {
    try {
      const r = await fetch(assetUrl);
      if (!r.ok) continue;
      const body = await r.text();
      assetsScanned.push(assetUrl);
      exposedSecrets.push(...scanTextForSecrets(body, assetUrl));
    } catch {
      /* skip unreachable asset */
    }
  }

  let robotsTxt: string | undefined;
  let sitemapFound = false;
  try {
    const robotsUrl = new URL('/robots.txt', finalUrl).toString();
    const rr = await fetch(robotsUrl);
    if (rr.ok) {
      robotsTxt = (await rr.text()).slice(0, 1000);
      sitemapFound = /sitemap/i.test(robotsTxt);
    }
  } catch {
    /* ignore */
  }

  const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
  const descMatch = html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i);

  const crawledSummaries = crawledPages.slice(0, 8).map((p) => ({
    url: p.url,
    title: p.title,
    excerpt: (p.text || '').slice(0, 300),
  }));

  return {
    targetUrl,
    finalUrl,
    statusCode: mainResp.status,
    headers,
    missingSecurityHeaders,
    technologies,
    assetsScanned,
    exposedSecrets: exposedSecrets.slice(0, 20),
    pageTitle: titleMatch?.[1],
    metaDescription: descMatch?.[1],
    robotsTxt,
    sitemapFound,
    crawledPageCount: crawledPages.length,
    crawledSummaries,
  };
}
