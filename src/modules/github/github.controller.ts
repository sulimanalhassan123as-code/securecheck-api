import { Router, Request, Response } from 'express';
import { alertCodeFindings } from '../../utils/telegram.util';

export const githubRouter = Router();

/**
 * GitHub Webhook Handler
 * 
 * Receives push events from GitHub. On every push:
 * 1. Fetches the list of changed files from the GitHub API
 * 2. Downloads and analyzes each file for security vulnerabilities
 * 3. Sends a Telegram alert if critical/high issues are found
 * 
 * Supported file types: .js, .ts, .jsx, .tsx, .py, .java, .php, .go, .rb, .env, .json, .yml, .yaml, .sh
 */

interface GitHubPushPayload {
  repository: {
    full_name: string;
    name: string;
    html_url: string;
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

// Security patterns to detect in source code
const SECURITY_PATTERNS: Array<{
  pattern: RegExp;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  recommendation: string;
}> = [
  // Hardcoded secrets
  {
    pattern: /(api[_-]?key|secret|password|passwd|token|auth|private[_-]?key)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    severity: 'CRITICAL',
    title: 'Hardcoded Secret Detected',
    description: 'A potential secret, API key, or password was found hardcoded in the source.',
    recommendation: 'Move secrets to environment variables or a secret manager. Never commit them to source code.',
  },
  // AWS keys
  {
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'CRITICAL',
    title: 'AWS Access Key ID Detected',
    description: 'An AWS access key ID was found in the source code.',
    recommendation: 'Rotate this key immediately and use IAM roles or environment variables instead.',
  },
  // Google API keys
  {
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: 'CRITICAL',
    title: 'Google API Key Detected',
    description: 'A Google API key was found in the source code.',
    recommendation: 'Restrict the key in Google Cloud Console and move it to environment variables.',
  },
  // Private keys (PEM)
  {
    pattern: /-----BEGIN [A-Z]+ PRIVATE KEY-----/g,
    severity: 'CRITICAL',
    title: 'Private Key Detected',
    description: 'A PEM private key was found in the source code.',
    recommendation: 'Remove this key immediately, rotate it, and use a secret manager.',
  },
  // SQL injection patterns
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
  // eval() usage
  {
    pattern: /\beval\s*\(/g,
    severity: 'HIGH',
    title: 'Use of eval()',
    description: 'eval() was used, which can execute arbitrary code and is a major security risk.',
    recommendation: 'Avoid eval(). Use JSON.parse() for data parsing or safer alternatives.',
  },
  // innerHTML / dangerouslySetInnerHTML (XSS)
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
  // Disabled security headers in code
  {
    pattern: /res\.setHeader\s*\(\s*['"]X-Frame-Options['"],\s*['"]DENY['"]\s*\)/gi,
    severity: 'LOW',
    title: 'X-Frame-Options Found (Good Practice)',
    description: 'X-Frame-Options header is being set — this is good practice.',
    recommendation: 'No action needed — this is a positive detection.',
  },
  // CORS misconfiguration
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
  // exec/spawn with shell
  {
    pattern: /child_process|exec\s*\(|execSync\s*\(/g,
    severity: 'MEDIUM',
    title: 'Child Process Execution',
    description: 'Child process execution detected — if used with untrusted input, this can lead to command injection.',
    recommendation: 'Avoid passing user input to exec(). Use execFile() with argument arrays instead.',
  },
  // Hardcoded database URLs
  {
    pattern: /(postgres|mongodb|mysql|redis):\/\/[^:]+:[^@]+@/gi,
    severity: 'CRITICAL',
    title: 'Hardcoded Database Connection String',
    description: 'A database connection string with credentials was found in the source.',
    recommendation: 'Move database URLs to environment variables. Rotate the exposed credentials.',
  },
  // JWT secret hardcoded
  {
    pattern: /jwt[_-]?secret\s*[:=]\s*['"][^'"]+['"]/gi,
    severity: 'HIGH',
    title: 'Hardcoded JWT Secret',
    description: 'A JWT secret was found hardcoded in the source code.',
    recommendation: 'Store JWT secrets in environment variables, never in source code.',
  },
  // http:// instead of https://
  {
    pattern: /fetch\s*\(\s*['"]http:\/\//gi,
    severity: 'MEDIUM',
    title: 'Insecure HTTP Request',
    description: 'An HTTP (non-HTTPS) request was detected. This exposes data to interception.',
    recommendation: 'Use HTTPS for all external requests to ensure encrypted communication.',
  },
  // fs.writeFile with user input (path traversal)
  {
    pattern: /fs\.(writeFile|writeFileSync|readFile|readFileSync)\s*\(.*req\./gi,
    severity: 'MEDIUM',
    title: 'Potential Path Traversal',
    description: 'File system operation with request data detected — this can lead to path traversal attacks.',
    recommendation: 'Sanitize and validate file paths before using them in file operations.',
  },
  // Process env with fallback to hardcoded values
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

  for (const rule of SECURITY_PATTERNS) {
    let match;
    while ((match = rule.pattern.exec(content)) !== null) {
      // Find which line this match is on
      const beforeMatch = content.slice(0, match.index);
      const lineNum = beforeMatch.split('\n').length;
      const lineContent = lines[lineNum - 1]?.trim() || '';

      // Skip comments and test files for lower severity items
      if (rule.severity === 'LOW' && (lineContent.startsWith('//') || lineContent.startsWith('#') || lineContent.startsWith('*'))) {
        continue;
      }

      // Skip .env.example files for secret detection
      if (filename.includes('.example') || filename.includes('.sample')) {
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

// POST /api/github/webhook — receives GitHub push events
githubRouter.post('/webhook', async (req: Request, res: Response) => {
  try {
    const event = req.header('X-GitHub-Event');
    
    if (event !== 'push') {
      return res.json({ success: true, message: `Ignored event: ${event}` });
    }

    const payload = req.body as GitHubPushPayload;
    const repoName = payload.repository?.full_name || 'unknown';
    const branch = payload.ref?.replace('refs/heads/', '') || 'unknown';
    const commitMsg = payload.commits?.[0]?.message || '';
    const pusher = payload.pusher?.name || 'unknown';

    console.log(`📥 GitHub webhook: push to ${repoName}:${branch} by ${pusher}`);

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

    console.log(`🔍 Scanning ${filesToScan.length} changed files in ${repoName}...`);

    // Fetch file contents from GitHub API
    // For public repos, we can use raw.githubusercontent.com
    // For private repos, we'd need a GitHub token (optional)
    const owner = repoName.split('/')[0];
    const repo = repoName.split('/')[1];
    const commitSha = payload.commits?.[0]?.id || 'HEAD';

    const allFindings: CodeFinding[] = [];

    // Process files in parallel (max 10 at a time)
    const batchSize = 10;
    for (let i = 0; i < filesToScan.length; i += batchSize) {
      const batch = filesToScan.slice(i, i + batchSize);
      const results = await Promise.allSettled(
        batch.map(async (filepath) => {
          try {
            // Try GitHub raw content URL (works for public repos)
            const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${commitSha}/${filepath}`;
            const res = await fetch(rawUrl, { signal: AbortSignal.timeout(10000) });
            if (!res.ok) return [];
            const content = await res.text();
            return analyzeFileContent(filepath, content);
          } catch {
            return [];
          }
        })
      );
      for (const result of results) {
        if (result.status === 'fulfilled') {
          allFindings.push(...result.value);
        }
      }
    }

    // Filter to only actionable findings (skip positive detections)
    const actionableFindings = allFindings.filter(f => f.severity !== 'LOW' || !f.title.includes('Good Practice'));
    const criticalHigh = actionableFindings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');

    console.log(`✅ Scan complete for ${repoName}: ${actionableFindings.length} findings (${criticalHigh.length} critical/high)`);

    // Send Telegram alert if CRITICAL or HIGH findings
    if (criticalHigh.length > 0) {
      try {
        await alertCodeFindings({
          repoName,
          branch,
          pusher,
          commitMsg: commitMsg.split('\n')[0],
          filesScanned: filesToScan.length,
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
      filesScanned: filesToScan.length,
      totalFindings: actionableFindings.length,
      criticalHigh: criticalHigh.length,
      findings: actionableFindings,
    });
  } catch (err: any) {
    console.error('GitHub webhook error:', err.message);
    res.json({ success: true, error: err.message }); // Always return 200 to GitHub
  }
});
