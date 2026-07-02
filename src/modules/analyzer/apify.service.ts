const APIFY_TOKEN = process.env.APIFY_TOKEN || '';
const APIFY_BASE = 'https://api.apify.com/v2';

export interface CrawledPage {
  url: string;
  title?: string;
  text?: string;
  html?: string;
}

/**
 * Crawls a target website using Apify's Website Content Crawler actor.
 * Runs synchronously and returns the dataset items (crawled pages).
 */
export async function crawlWebsiteWithApify(targetUrl: string, maxPages = 8): Promise<CrawledPage[]> {
  if (!APIFY_TOKEN) {
    throw new Error('APIFY_TOKEN is not configured on the server.');
  }

  const actorId = 'apify~website-content-crawler';
  const runInput = {
    startUrls: [{ url: targetUrl }],
    maxCrawlPages: maxPages,
    crawlerType: 'cheerio',
    saveHtml: true,
    saveMarkdown: false,
    maxCrawlDepth: 2,
    proxyConfiguration: { useApifyProxy: true },
  };

  const resp = await fetch(
    `${APIFY_BASE}/acts/${actorId}/run-sync-get-dataset-items?token=${APIFY_TOKEN}&timeout=90`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(runInput),
    }
  );

  if (!resp.ok) {
    const errText = await resp.text().catch(() => '');
    throw new Error(`Apify crawl failed (${resp.status}): ${errText.slice(0, 300)}`);
  }

  const items = (await resp.json()) as any[];
  return items.map((it) => ({
    url: it.url,
    title: it.metadata?.title || it.title,
    text: it.text,
    html: it.html,
  }));
}
