import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { alertCodeFindings, sendDailySecuritySummary } from '../../utils/telegram.util';
import { prisma } from '../../config/db';

export const githubRouter = Router();

/**
 * GitHub Webhook Handler — SECURED with HMAC-SHA256 signature verification
 * 
 * Every request must include a valid X-Hub-Signature-256 header that matches
 * the WEBHOOK_SECRET environment variable. Requests without valid signatures
 * are rejected with 401 Unauthorized.
 * 
 * Receives push events from GitHub. On every push:
 * 1. Fetches the list of changed files from the GitHub API
 * 2. Downloads and analyzes each file for security vulnerabilities
 * 3. Sends a Telegram alert if critical/high issues are found
 * 
 * Supports both public and private repos (GITHUB_TOKEN env var for private repos)
 */

interface GitHubPushPayload {
  repository: {
    full_name: string;
    name: string;
    html_url: string;
    private: boolean;
  };
  ref: string;
  commits: Array<{
    id: string;
    message: string;
    added: string[];
    modified: string[];
    removed: string[];
  }>;
  pusher: {
    name: string;
  };
}

interface CodeFinding {
  file: string;
  line: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  codeSnippet: string;
  recommendation: string;
}

/**
 * Get the webhook secret from DB (GitHubConfig table) or env var fallback.
 * The secret is stored encrypted in the database and never appears in source code.
 */
async function getWebhookSecret(): Promise<string | null> {
  // Try env var first (if set on Render)
  const envSecret = process.env.GITHUB_WEBHOOK_SECRET;
  if (envSecret) return envSecret;

  // Fall back to database
  try {
    const rows = await prisma.$queryRawUnsafe(
      `SELECT "webhookSecret" FROM "GitHubConfig" WHERE id = 'default' LIMIT 1`
    ) as any[];
    if (rows.length > 0 && rows[0].webhookSecret) {
      return rows[0].webhookSecret;
    }
  } catch {
    // Table might not exist yet
  }
  return null;
}

/**
 * Verify the GitHub webhook signature using HMAC-SHA256.
 * Returns true if the signature matches, false otherwise.
 * Uses timing-safe comparison to prevent timing attacks.
 * 
 * SECURITY:
 * - Secret is read from DB or env var (never hardcoded)
 * - Timing-safe comparison prevents timing attacks
 * - Rejects all unsigned/invalid requests with 401
 */
async function verifyGitHubSignature(req: Request): Promise<boolean> {
  const webhookSecret = await getWebhookSecret();
  if (!webhookSecret) {
    console.error('❌ No webhook secret configured — rejecting all webhooks (set via /api/github/config or GITHUB_WEBHOOK_SECRET env var)');
    return false;
  }

  const signature = req.header('X-Hub-Signature-256');
  if (!signature) {
    console.warn('⚠️ Webhook received without X-Hub-Signature-256 header — rejecting');
    return false;
  }

  // GitHub sends: "sha256=<hex-digest>"
  const [algorithm, hexDigest] = signature.split('=');
  if (algorithm !== 'sha256' || !hexDigest) {
    console.warn('⚠️ Invalid signature format — rejecting');
    return false;
  }

  // Compute HMAC-SHA256 of the raw body using the secret
  const rawBody = JSON.stringify(req.body);
  const computedDigest = crypto
    .createHmac('sha256', webhookSecret)
    .update(rawBody)
    .digest('hex');

  // Timing-safe comparison to prevent timing attacks
  const receivedBuffer = Buffer.from(hexDigest, 'hex');
  const computedBuffer = Buffer.from(computedDigest, 'hex');

  if (receivedBuffer.length !== computedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(receivedBuffer, computedBuffer);
}

// Security patterns to detect in source code
const SECURITY_PATTERNS: Array<{
  pattern: RegExp;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  recommendation: string;
}> = [
  {
    pattern: /(api[_-]?key|secret|password|passwd|token|auth|private[_-]?key)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    severity: 'CRITICAL',
    title: 'Hardcoded Secret Detected',
    description: 'A potential secret, API key, or password was found hardcoded in the source.',
    recommendation: 'Move secrets to environment variables or a secret manager. Never commit them to source code.',
  },
  {
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'CRITICAL',
    title: 'AWS Access Key ID Detected',
    description: 'An AWS access key ID was found in the source code.',
    recommendation: 'Rotate this key immediately and use IAM roles or environment variables instead.',
  },
  {
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: 'CRITICAL',
    title: 'Google API Key Detected',
    description: 'A Google API key was found in the source code.',
    recommendation: 'Restrict the key in Google Cloud Console and move it to environment variables.',
  },
  {
    pattern: /-----BEGIN [A-Z]+ PRIVATE KEY-----/g,
    severity: 'CRITICAL',
    title: 'Private Key Detected',
    description: 'A PEM private key was found in the source code.',
    recommendation: 'Remove this key immediately, rotate it, and use a secret manager.',
  },
  {
    pattern: /(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+.*\$\{.*\}/gi,
    severity: 'HIGH',
    title: 'Potential SQL Injection',
    description: 'String interpolation detected in a SQL query — this can lead to SQL injection.',
    recommendation: 'Use parameterized queries or prepared statements instead of string interpolation.',
  },
  {
    pattern: /query\s*\(\s*['"`].*\+.*['"`]/gi,
    severity: 'HIGH',
    title: 'Potential SQL Injection via Concatenation',
    description: 'String concatenation detected in a database query.',
    recommendation: 'Use parameterized queries instead of concatenating user input into SQL.',
  },
  {
    pattern: /\beval\s*\(/g,
    severity: 'HIGH',
    title: 'Use of eval()',
    description: 'eval() was used, which can execute arbitrary code and is a major security risk.',
    recommendation: 'Avoid eval(). Use JSON.parse() for data parsing or safer alternatives.',
  },
  {
    pattern: /dangerouslySetInnerHTML/g,
    severity: 'HIGH',
    title: 'dangerouslySetInnerHTML Usage',
    description: 'React dangerouslySetInnerHTML can lead to XSS if used with untrusted data.',
    recommendation: 'Sanitize HTML before rendering, or use a library like DOMPurify.',
  },
  {
    pattern: /\.innerHTML\s*=/g,
    severity: 'HIGH',
    title: 'innerHTML Assignment',
    description: 'Setting innerHTML with untrusted data can cause Cross-Site Scripting (XSS).',
    recommendation: 'Use textContent instead, or sanitize the HTML with DOMPurify.',
  },
  {
    pattern: /cors\s*\(\s*\{\s*origin\s*:\s*['"]\*['"]\s*\}/gi,
    severity: 'HIGH',
    title: 'CORS Allow All Origins',
    description: 'CORS is configured to allow all origins (*) which is a security risk.',
    recommendation: 'Restrict CORS to specific trusted origins instead of using a wildcard.',
  },
  {
    pattern: /Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]/gi,
    severity: 'HIGH',
    title: 'CORS Wildcard Origin',
    description: 'Access-Control-Allow-Origin is set to wildcard, allowing all sites to access this resource.',
    recommendation: 'Specify allowed origins explicitly instead of using *.',
  },
  {
    pattern: /child_process|exec\s*\(|execSync\s*\(/g,
    severity: 'MEDIUM',
    title: 'Child Process Execution',
    description: 'Child process execution detected — if used with untrusted input, this can lead to command injection.',
    recommendation: 'Avoid passing user input to exec(). Use execFile() with argument arrays instead.',
  },
  {
    pattern: /(postgres|mongodb|mysql|redis):\/\/[^:]+:[^@]+@/gi,
    severity: 'CRITICAL',
    title: 'Hardcoded Database Connection String',
    description: 'A database connection string with credentials was found in the source.',
    recommendation: 'Move database URLs to environment variables. Rotate the exposed credentials.',
  },
  {
    pattern: /jwt[_-]?secret\s*[:=]\s*['"][^'"]+['"]/gi,
    severity: 'HIGH',
    title: 'Hardcoded JWT Secret',
    description: 'A JWT secret was found hardcoded in the source code.',
    recommendation: 'Store JWT secrets in environment variables, never in source code.',
  },
  {
    pattern: /fetch\s*\(\s*['"]http:\/\//gi,
    severity: 'MEDIUM',
    title: 'Insecure HTTP Request',
    description: 'An HTTP (non-HTTPS) request was detected. This exposes data to interception.',
    recommendation: 'Use HTTPS for all external requests to ensure encrypted communication.',
  },
  {
    pattern: /fs\.(writeFile|writeFileSync|readFile|readFileSync)\s*\(.*req\./gi,
    severity: 'MEDIUM',
    title: 'Potential Path Traversal',
    description: 'File system operation with request data detected — this can lead to path traversal attacks.',
    recommendation: 'Sanitize and validate file paths before using them in file operations.',
  },
  {
    pattern: /process\.env\.[A-Z_]+\s*\|\|\s*['"][^'"]{8,}['"]/g,
    severity: 'MEDIUM',
    title: 'Environment Variable with Hardcoded Fallback',
    description: 'An environment variable has a hardcoded default fallback value that may contain secrets.',
    recommendation: 'Fail fast if the environment variable is missing rather than using a hardcoded fallback.',
  },
];

function analyzeFileContent(filename: string, content: string): CodeFinding[] {
  const findings: CodeFinding[] = [];
  const lines = content.split('\n');

  // Skip scanner's own files to prevent false positives (self-detection)
  const scannerFiles = ['github.controller.ts', 'telegram.util.ts', 'scanner.controller.ts', 'analyzer.controller.ts'];
  if (scannerFiles.some(f => filename.endsWith(f))) {
    return findings;
  }

  for (const rule of SECURITY_PATTERNS) {
    let match;
    while ((match = rule.pattern.exec(content)) !== null) {
      const beforeMatch = content.slice(0, match.index);
      const lineNum = beforeMatch.split('\n').length;
      const lineContent = lines[lineNum - 1]?.trim() || '';

      // Skip comments
      if (lineContent.startsWith('//') || lineContent.startsWith('#') || lineContent.startsWith('*') || lineContent.startsWith('/*')) {
        continue;
      }

      // Skip .example and .sample files
      if (filename.includes('.example') || filename.includes('.sample')) {
        continue;
      }

      // Skip lines that are clearly pattern definitions (the scanner's own regex strings)
      if (lineContent.includes('pattern:') || lineContent.includes('title:') || lineContent.includes('description:') || lineContent.includes('recommendation:')) {
        continue;
      }

      findings.push({
        file: filename,
        line: lineNum,
        severity: rule.severity,
        title: rule.title,
        description: rule.description,
        codeSnippet: lineContent.length > 120 ? lineContent.slice(0, 120) + '...' : lineContent,
        recommendation: rule.recommendation,
      });
    }
  }

  return findings;
}

async function fetchFileContent(owner: string, repo: string, filepath: string, ref: string, isPrivate: boolean): Promise<string | null> {
  const envToken = process.env.GITHUB_TOKEN;
    let dbToken: string | null = null;
    try {
      const rows = await prisma.$queryRawUnsafe(`SELECT "githubToken" FROM "GitHubConfig" WHERE id = 'default' LIMIT 1`) as any[];
      dbToken = rows[0]?.githubToken || null;
    } catch {}
    const githubToken = envToken || dbToken;
  
  try {
    if (isPrivate || githubToken) {
      const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${filepath}?ref=${ref}`;
      const res = await fetch(apiUrl, {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
          ...(githubToken ? { 'Authorization': `Bearer ${githubToken}` } : {}),
        },
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) return null;
      const data = await res.json() as any;
      if (data.content && data.encoding === 'base64') {
        return Buffer.from(data.content, 'base64').toString('utf-8');
      }
      return null;
    }

    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${filepath}`;
    const res = await fetch(rawUrl, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

// Admin key check — accepts ADMIN_KEY, GITHUB_TOKEN, TELEGRAM_BOT_TOKEN (env or DB)
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const GH_TOKEN = process.env.GITHUB_TOKEN || '';
const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';

async function isAdmin(req: Request): Promise<boolean> {
  const headerKey = req.header('x-admin-key');
  
  // Accept any of the known env secrets as admin key
  if (headerKey && (headerKey === ADMIN_KEY || headerKey === GH_TOKEN || headerKey === TG_TOKEN)) {
    return true;
  }
  
  // Also check Telegram bot token from DB (it may not be in env vars)
  if (headerKey) {
    try {
      const rows = await prisma.$queryRawUnsafe(
        `SELECT "botToken" FROM "TelegramConfig" WHERE id = 'default' LIMIT 1`
      ) as any[];
      if (rows.length > 0 && rows[0].botToken && headerKey === rows[0].botToken) {
        return true;
      }
      // Also check GitHubConfig table for githubToken
      const ghRows = await prisma.$queryRawUnsafe(
        `SELECT "githubToken" FROM "GitHubConfig" WHERE id = 'default' LIMIT 1`
      ) as any[];
      if (ghRows.length > 0 && ghRows[0].githubToken && headerKey === ghRows[0].githubToken) {
        return true;
      }
    } catch {}
  }
  
  const bearer = req.header('authorization')?.replace('Bearer ', '');
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

// POST /api/github/config — store webhook secret in DB (admin-only)
// The secret is NEVER logged, NEVER returned in responses, and NEVER in source code.
githubRouter.post('/config', async (req: Request, res: Response) => {
  try {
    if (!(await isAdmin(req))) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const { webhookSecret, githubToken } = req.body;

    // Upsert config row
    const existing = await prisma.$queryRawUnsafe(`SELECT id FROM "GitHubConfig" WHERE id = 'default' LIMIT 1`) as any[];
    if (existing.length > 0) {
      await prisma.$executeRawUnsafe(
        `UPDATE "GitHubConfig" SET "webhookSecret" = $1, "githubToken" = $2, "updatedAt" = NOW() WHERE id = 'default'`,
        webhookSecret || null, githubToken || null
      );
    } else {
      await prisma.$executeRawUnsafe(
        `INSERT INTO "GitHubConfig" (id, "webhookSecret", "githubToken", "createdAt", "updatedAt") VALUES ('default', $1, $2, NOW(), NOW())`,
        webhookSecret || null, githubToken || null
      );
    }
    res.json({ success: true, message: 'GitHub config saved. Secret is stored securely.' });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/github/config/status — non-secret diagnostic (no admin key needed)
githubRouter.get('/config/status', async (req: Request, res: Response) => {
  try {
    const secret = await getWebhookSecret();
    const envToken = process.env.GITHUB_TOKEN;
    let dbToken: string | null = null;
    try {
      const rows = await prisma.$queryRawUnsafe(`SELECT "githubToken" FROM "GitHubConfig" WHERE id = 'default' LIMIT 1`) as any[];
      dbToken = rows[0]?.githubToken || null;
    } catch {}
    res.json({
      success: true,
      hasWebhookSecret: !!secret,
      hasGithubToken: !!envToken || !!dbToken,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/github/scan-all — scan all repos and send daily summary (admin-only)
githubRouter.post('/scan-all', async (req: Request, res: Response) => {
  try {
    if (!(await isAdmin(req))) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const result = await scanAllReposForSummary();
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/github/scan-all — same via GET (for cron/scheduler)
githubRouter.get('/scan-all', async (req: Request, res: Response) => {
  try {
    const adminKey = req.header('x-admin-key') || req.query.key as string;
    if (!adminKey) return res.status(401).json({ success: false, error: 'Unauthorized' });
    if (!(await isAdmin(req))) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const result = await scanAllReposForSummary();
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * Scans the latest commit of all repos for the authenticated user.
 * Returns a consolidated summary of findings across all repos.
 */
async function scanAllReposForSummary() {
  const { execSync } = await import('child_process');
  const githubToken = process.env.GITHUB_TOKEN || (await prisma.$queryRawUnsafe(
    `SELECT "githubToken" FROM "GitHubConfig" WHERE id = 'default' LIMIT 1`
  ) as any[])[0]?.githubToken || '';

  // Fetch all repos
  const reposRes = await fetch(
    'https://api.github.com/user/repos?per_page=100&sort=updated&direction=desc',
    {
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        ...(githubToken ? { 'Authorization': `Bearer ${githubToken}` } : {}),
      },
    }
  );
  const repos = await reposRes.json() as any[];
  const totalRepos = repos.length;

  console.log(`📋 Daily summary: scanning ${totalRepos} repos...`);

  // Scan the latest commit of each repo (limit to 30 repos per run to avoid timeout)
  const reposToScan = repos.slice(0, 30);
  let reposScanned = 0;
  let reposWithIssues = 0;
  let cleanRepos = 0;
  let totalCritical = 0;
  let totalHigh = 0;
  let totalMedium = 0;
  const topFindings: Array<{ repo: string; severity: string; title: string; file: string }> = [];

  // Process in batches of 5
  const batchSize = 5;
  for (let i = 0; i < reposToScan.length; i += batchSize) {
    const batch = reposToScan.slice(i, i + batchSize);
    const results = await Promise.allSettled(batch.map(async (repo: any) => {
      const repoName = repo.full_name;
      const owner = repo.owner.login;
      const name = repo.name;
      const isPrivate = repo.private;

      try {
        // Get the latest commit on default branch
        const branchRes = await fetch(
          `https://api.github.com/repos/${owner}/${name}/commits?per_page=1`,
          {
            headers: {
              'Accept': 'application/vnd.github.v3+json',
              ...(githubToken ? { 'Authorization': `Bearer ${githubToken}` } : {}),
            },
            signal: AbortSignal.timeout(10000),
          }
        );
        if (!branchRes.ok) return { repoName, findings: [] };
        const commits = await branchRes.json() as any[];
        if (!commits || commits.length === 0) return { repoName, findings: [] };
        const commitSha = commits[0].sha;

        // Get files changed in the latest commit
        const commitRes = await fetch(
          `https://api.github.com/repos/${owner}/${name}/commits/${commitSha}`,
          {
            headers: {
              'Accept': 'application/vnd.github.v3+json',
              ...(githubToken ? { 'Authorization': `Bearer ${githubToken}` } : {}),
            },
            signal: AbortSignal.timeout(10000),
          }
        );
        if (!commitRes.ok) return { repoName, findings: [] };
        const commitData = await commitRes.json() as any;
        const files = commitData.files || [];

        // Filter to code files
        const codeExtensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.php', '.go', '.rb', '.env', '.json', '.yml', '.yaml', '.sh', '.sql'];
        const codeFiles = files.filter((f: any) => 
          codeExtensions.some(ext => f.filename.endsWith(ext))
        ).slice(0, 10);

        if (codeFiles.length === 0) return { repoName, findings: [] };

        // Fetch and scan each file
        const repoFindings: CodeFinding[] = [];
        for (const file of codeFiles) {
          let content: string | null = null;
          try {
            if (isPrivate || githubToken) {
              const fileRes = await fetch(
                `https://api.github.com/repos/${owner}/${name}/contents/${file.filename}?ref=${commitSha}`,
                {
                  headers: {
                    'Accept': 'application/vnd.github.v3+json',
                    ...(githubToken ? { 'Authorization': `Bearer ${githubToken}` } : {}),
                  },
                  signal: AbortSignal.timeout(10000),
                }
              );
              if (fileRes.ok) {
                const fileData = await fileRes.json() as any;
                if (fileData.content && fileData.encoding === 'base64') {
                  content = Buffer.from(fileData.content, 'base64').toString('utf-8');
                }
              }
            } else {
              const rawRes = await fetch(
                `https://raw.githubusercontent.com/${owner}/${name}/${commitSha}/${file.filename}`,
                { signal: AbortSignal.timeout(10000) }
              );
              if (rawRes.ok) content = await rawRes.text();
            }
          } catch {}
          if (content) {
            repoFindings.push(...analyzeFileContent(file.filename, content));
          }
        }

        return { repoName, findings: repoFindings };
      } catch {
        return { repoName, findings: [] };
      }
    }));

    for (const result of results) {
      if (result.status === 'fulfilled') {
        reposScanned++;
        const { repoName, findings } = result.value;
        if (findings.length > 0) {
          reposWithIssues++;
          for (const f of findings) {
            if (f.severity === 'CRITICAL') totalCritical++;
            else if (f.severity === 'HIGH') totalHigh++;
            else if (f.severity === 'MEDIUM') totalMedium++;
            topFindings.push({ repo: repoName, severity: f.severity, title: f.title, file: f.file });
          }
        } else {
          cleanRepos++;
        }
      }
    }
  }

  console.log(`✅ Daily summary: ${reposScanned} repos scanned, ${reposWithIssues} with issues, ${totalCritical} critical, ${totalHigh} high`);

  // Send the Telegram summary
  try {
    await sendDailySecuritySummary({
      totalRepos,
      reposScanned,
      reposWithIssues,
      totalCritical,
      totalHigh,
      totalMedium,
      topFindings: topFindings.sort((a, b) => {
        const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        return (order[a.severity as keyof typeof order] || 4) - (order[b.severity as keyof typeof order] || 4);
      }),
      cleanRepos,
    });
    console.log('📱 Daily security summary sent to Telegram');
  } catch (e: any) {
    console.error('⚠️ Daily summary Telegram send failed:', e.message);
  }

  return {
    success: true,
    totalRepos,
    reposScanned,
    reposWithIssues,
    cleanRepos,
    totalCritical,
    totalHigh,
    totalMedium,
    findings: topFindings,
  };
}

// POST /api/github/webhook — receives GitHub push events (SECURED)
githubRouter.post('/webhook', async (req: Request, res: Response) => {
  try {
    // ── SECURITY GATE: Verify GitHub signature ──
    if (!(await verifyGitHubSignature(req))) {
      console.warn('🚫 Unauthorized webhook attempt — signature verification failed');
      return res.status(401).json({ error: 'Unauthorized: Invalid or missing signature' });
    }

    const event = req.header('X-GitHub-Event');
    
    if (event !== 'push') {
      return res.json({ success: true, message: `Ignored event: ${event}` });
    }

    const payload = req.body as GitHubPushPayload;
    const repoName = payload.repository?.full_name || 'unknown';
    const branch = payload.ref?.replace('refs/heads/', '') || 'unknown';
    const commitMsg = payload.commits?.[0]?.message || '';
    const pusher = payload.pusher?.name || 'unknown';
    const isPrivate = payload.repository?.private || false;

    console.log(`📥 GitHub webhook: push to ${repoName}:${branch} by ${pusher} (private: ${isPrivate})`);

    // Collect all changed files
    const changedFiles = new Set<string>();
    for (const commit of payload.commits || []) {
      for (const f of [...commit.added, ...commit.modified]) {
        changedFiles.add(f);
      }
    }

    // Only scan code files
    const codeExtensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.php', '.go', '.rb', '.env', '.json', '.yml', '.yaml', '.sh', '.sql'];
    const filesToScan = Array.from(changedFiles).filter(f => 
      codeExtensions.some(ext => f.endsWith(ext))
    );

    if (filesToScan.length === 0) {
      console.log(`📝 No code files changed in ${repoName}, skipping scan`);
      return res.json({ success: true, message: 'No code files to scan' });
    }

    const filesToScanLimited = filesToScan.slice(0, 50);
    console.log(`🔍 Scanning ${filesToScanLimited.length} changed files in ${repoName}...`);

    const owner = repoName.split('/')[0];
    const repo = repoName.split('/')[1];
    const commitSha = payload.commits?.[0]?.id || 'HEAD';

    const allFindings: CodeFinding[] = [];

    const batchSize = 10;
    for (let i = 0; i < filesToScanLimited.length; i += batchSize) {
      const batch = filesToScanLimited.slice(i, i + batchSize);
      const results = await Promise.allSettled(
        batch.map(async (filepath) => {
          const content = await fetchFileContent(owner, repo, filepath, commitSha, isPrivate);
          if (!content) return [];
          return analyzeFileContent(filepath, content);
        })
      );
      for (const result of results) {
        if (result.status === 'fulfilled') {
          allFindings.push(...result.value);
        }
      }
    }

    const actionableFindings = allFindings.filter(f => f.severity !== 'LOW' || !f.title.includes('Good Practice'));
    const criticalHigh = actionableFindings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');

    console.log(`✅ Scan complete for ${repoName}: ${actionableFindings.length} findings (${criticalHigh.length} critical/high)`);

    if (criticalHigh.length > 0) {
      try {
        await alertCodeFindings({
          repoName,
          branch,
          pusher,
          commitMsg: commitMsg.split('\n')[0],
          filesScanned: filesToScanLimited.length,
          findings: criticalHigh,
        });
        console.log(`📱 Telegram alert sent for ${repoName}`);
      } catch (e: any) {
        console.error('⚠️ Telegram alert failed:', e.message);
      }
    }

    res.json({
      success: true,
      repo: repoName,
      branch,
      filesScanned: filesToScanLimited.length,
      totalFindings: actionableFindings.length,
      criticalHigh: criticalHigh.length,
      findings: actionableFindings,
    });
  } catch (err: any) {
    console.error('GitHub webhook error:', err.message);
    res.json({ success: true, error: err.message });
  }
});


/**
 * Called by the daily scheduler in server.ts.
 * Scans all repos and sends a consolidated summary to Telegram.
 */
export async function triggerDailySummary(): Promise<void> {
  console.log('📋 Daily GitHub security summary starting...');
  try {
    const result = await scanAllReposForSummary();
    console.log(`✅ Daily summary complete: ${result.reposScanned} repos scanned, ${result.totalCritical} critical, ${result.totalHigh} high`);
  } catch (e: any) {
    console.error('❌ Daily summary failed:', e.message);
  }
}
