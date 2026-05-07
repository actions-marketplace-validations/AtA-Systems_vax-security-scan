const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ACTION_VERSION = '0.1.0';
const DEFAULT_EXCLUDES = new Set([
  '.git',
  '.hg',
  '.svn',
  'node_modules',
  'vendor',
  'dist',
  'build',
  'coverage',
  '.next',
  '.nuxt',
  '.turbo',
  '.cache',
  '__pycache__',
  '.venv',
  'venv'
]);

const TEXT_EXTENSIONS = new Set([
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.py',
  '.go',
  '.rs',
  '.java',
  '.kt',
  '.cs',
  '.rb',
  '.php',
  '.c',
  '.h',
  '.cpp',
  '.hpp',
  '.swift',
  '.scala',
  '.sh',
  '.bash',
  '.zsh',
  '.ps1',
  '.yaml',
  '.yml',
  '.json',
  '.toml',
  '.ini',
  '.cfg',
  '.conf',
  '.xml',
  '.html',
  '.css',
  '.scss',
  '.sql',
  '.md',
  '.mdx',
  '.txt',
  '.env.example',
  '.dockerfile'
]);

const IMPORTANT_NAMES = new Set([
  'package.json',
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'requirements.txt',
  'pyproject.toml',
  'poetry.lock',
  'Pipfile',
  'Pipfile.lock',
  'go.mod',
  'go.sum',
  'Cargo.toml',
  'Cargo.lock',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'Dockerfile',
  'docker-compose.yml',
  'docker-compose.yaml',
  'README.md',
  'SECURITY.md',
  'CODEOWNERS',
  'dependabot.yml',
  'renovate.json'
]);

class FatalConfigurationError extends Error {}

function inputName(name) {
  return `INPUT_${name.replace(/ /g, '_').toUpperCase()}`;
}

function getInput(name, fallback = '') {
  return process.env[inputName(name)] || fallback;
}

function setFailed(message) {
  console.error(`::error::${escapeCommand(message)}`);
  process.exitCode = 1;
}

function setOutput(name, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    fs.appendFileSync(outputFile, `${name}=${value}\n`, 'utf8');
  } else {
    console.log(`::set-output name=${name}::${escapeCommand(value)}`);
  }
}

function addSummary(markdown) {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) {
    fs.appendFileSync(summaryFile, `${markdown}\n`, 'utf8');
  }
}

function escapeCommand(value) {
  return String(value).replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function parseList(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseNumber(value, fallback) {
  const parsed = Number.parseInt(String(value || ''), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function isProbablyTextFile(filePath) {
  const base = path.basename(filePath);
  const ext = path.extname(filePath).toLowerCase();
  return TEXT_EXTENSIONS.has(ext) || IMPORTANT_NAMES.has(base) || base.startsWith('.env.');
}

function shouldSkipDirectory(dirName) {
  return DEFAULT_EXCLUDES.has(dirName);
}

function walkEvidencePaths(root, requestedPaths, maxFiles) {
  const discovered = [];
  const queue = requestedPaths.map((item) => path.resolve(root, item));

  while (queue.length > 0 && discovered.length < maxFiles * 4) {
    const current = queue.shift();
    if (!current || !fs.existsSync(current)) {
      continue;
    }

    const stat = fs.statSync(current);
    if (stat.isDirectory()) {
      const entries = fs.readdirSync(current, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory() && shouldSkipDirectory(entry.name)) {
          continue;
        }
        queue.push(path.join(current, entry.name));
      }
      continue;
    }

    if (stat.isFile() && isProbablyTextFile(current)) {
      discovered.push(current);
    }
  }

  return prioritizeFiles(root, discovered).slice(0, maxFiles);
}

function prioritizeFiles(root, files) {
  return files.sort((left, right) => {
    const leftRel = path.relative(root, left);
    const rightRel = path.relative(root, right);
    const leftScore = filePriority(leftRel);
    const rightScore = filePriority(rightRel);
    if (leftScore !== rightScore) return rightScore - leftScore;
    return leftRel.localeCompare(rightRel);
  });
}

function filePriority(relativePath) {
  const base = path.basename(relativePath);
  let score = 0;
  if (IMPORTANT_NAMES.has(base)) score += 50;
  if (relativePath.includes('.github/workflows/')) score += 40;
  if (/security|auth|session|login|password|oauth|oidc|jwt|csrf|cors/i.test(relativePath)) score += 30;
  if (/src|app|lib|server|api/i.test(relativePath)) score += 10;
  return score;
}

function detectLanguage(relativePath) {
  const ext = path.extname(relativePath).toLowerCase();
  const map = {
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.py': 'python',
    '.go': 'go',
    '.rs': 'rust',
    '.java': 'java',
    '.rb': 'ruby',
    '.php': 'php',
    '.cs': 'csharp',
    '.kt': 'kotlin',
    '.swift': 'swift'
  };
  return map[ext] || null;
}

function scanRepository(root, options) {
  const files = walkEvidencePaths(root, options.evidencePaths, options.maxFiles);
  const evidence = [];
  const languages = {};
  const manifests = [];
  const securityFiles = [];
  const localSignals = new Map();
  let bytesIncluded = 0;
  let truncated = false;

  for (const filePath of files) {
    const relativePath = path.relative(root, filePath).replace(/\\/g, '/');
    const raw = fs.readFileSync(filePath);
    const fileHash = sha256(raw);
    const base = path.basename(relativePath);
    const language = detectLanguage(relativePath);
    if (language) languages[language] = (languages[language] || 0) + 1;
    if (IMPORTANT_NAMES.has(base) || /lock$|lock\.json$|\.lock$/i.test(base)) manifests.push(relativePath);
    if (/security|auth|session|login|password|oauth|oidc|jwt|csrf|cors|dependabot|codeowners/i.test(relativePath)) {
      securityFiles.push(relativePath);
    }

    const remaining = options.maxBytes - bytesIncluded;
    if (remaining <= 0) {
      truncated = true;
      break;
    }

    const maxForFile = Math.min(options.maxFileBytes, remaining);
    const content = raw.toString('utf8', 0, maxForFile);
    bytesIncluded += Buffer.byteLength(content, 'utf8');
    if (raw.length > maxForFile) truncated = true;

    collectLocalSignals(relativePath, content, localSignals);
    evidence.push({
      path: relativePath,
      sha256: fileHash,
      size: raw.length,
      truncated: raw.length > maxForFile,
      content
    });
  }

  return {
    evidence,
    evidence_truncated: truncated,
    scan_summary: {
      filesDiscovered: files.length,
      filesScanned: evidence.length,
      bytesIncluded,
      languages,
      manifests: manifests.slice(0, 80),
      securityFiles: securityFiles.slice(0, 80),
      localFindings: Array.from(localSignals.values())
    }
  };
}

function addSignal(signals, id, title, severity, filePath) {
  if (!signals.has(id)) {
    signals.set(id, { id, title, severity, paths: [] });
  }
  const signal = signals.get(id);
  if (!signal.paths.includes(filePath)) signal.paths.push(filePath);
}

function collectLocalSignals(relativePath, content, signals) {
  if (/password|secret|api[_-]?key/i.test(content)) {
    addSignal(signals, 'secret-keyword', 'Secret-related keywords found', 'info', relativePath);
  }
  if (/cors\(\s*\{?[^}]*origin\s*:\s*['"]\*/i.test(content) || /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*/i.test(content)) {
    addSignal(signals, 'wide-cors', 'Potential wildcard CORS configuration', 'medium', relativePath);
  }
  if (/csrf/i.test(content)) {
    addSignal(signals, 'csrf-signal', 'CSRF handling appears in code', 'info', relativePath);
  }
  if (/helmet|Content-Security-Policy|Strict-Transport-Security|X-Content-Type-Options/i.test(content)) {
    addSignal(signals, 'security-headers', 'Security header controls appear in code', 'info', relativePath);
  }
  if (/jwt|oidc|oauth|saml|session/i.test(content)) {
    addSignal(signals, 'authn-authz-signal', 'Authentication or session logic appears in code', 'info', relativePath);
  }
}

async function getGitHubOidcToken(audience) {
  const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!requestUrl || !requestToken) {
    throw new FatalConfigurationError('GitHub OIDC is unavailable. Add `permissions: id-token: write` to the workflow.');
  }
  const url = `${requestUrl}${requestUrl.includes('?') ? '&' : '?'}audience=${encodeURIComponent(audience)}`;
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${requestToken}`,
      Accept: 'application/json'
    }
  });
  if (!response.ok) {
    throw new Error(`Unable to request GitHub OIDC token: ${response.status} ${await response.text()}`);
  }
  const body = await response.json();
  if (!body.value) {
    throw new FatalConfigurationError('GitHub OIDC response did not include a token.');
  }
  return body.value;
}

async function uploadRun(endpoint, payload) {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-VAX-Key': payload.vax_key,
      'User-Agent': `vax-action/${ACTION_VERSION}`
    },
    body: JSON.stringify(payload)
  });
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { raw: text };
  }
  if (!response.ok) {
    throw new Error(`VAX upload failed: ${response.status} ${JSON.stringify(body)}`);
  }
  return body;
}

async function main() {
  const vaxKey = getInput('vax_key') || process.env.VAX_KEY;
  const endpoint = getInput('endpoint', 'https://us-central1-vax-ata-systems.cloudfunctions.net/action_start_run');
  const scanLevels = parseList(getInput('scan_levels', 'asvs-l1,asvs-l2'));
  const evidencePaths = parseList(getInput('evidence_paths', '.'));
  const maxFiles = parseNumber(getInput('max_files', '120'), 120);
  const maxBytes = parseNumber(getInput('max_bytes', '750000'), 750000);
  const maxFileBytes = parseNumber(getInput('max_file_bytes', '24000'), 24000);

  if (!vaxKey) {
    throw new FatalConfigurationError('VAX key is required. Set `with.vax_key` or env `VAX_KEY` from `${{ secrets.VAX_KEY }}`.');
  }

  const root = process.env.GITHUB_WORKSPACE || process.cwd();
  const oidcToken = await getGitHubOidcToken('vax');
  const scan = scanRepository(root, { evidencePaths, maxFiles, maxBytes, maxFileBytes });

  const payload = {
    vax_key: vaxKey,
    github_oidc_token: oidcToken,
    action_version: ACTION_VERSION,
    repository: process.env.GITHUB_REPOSITORY,
    ref: process.env.GITHUB_REF,
    sha: process.env.GITHUB_SHA,
    workflow: process.env.GITHUB_WORKFLOW,
    github_run_id: process.env.GITHUB_RUN_ID,
    github_run_attempt: process.env.GITHUB_RUN_ATTEMPT,
    scan_levels: scanLevels,
    evidence: scan.evidence,
    evidence_truncated: scan.evidence_truncated,
    scan_summary: scan.scan_summary
  };

  try {
    const result = await uploadRun(endpoint, payload);
    const runUrl = result.run_url;
    setOutput('run_url', runUrl);
    setOutput('run_id', result.run_id);

    console.log(`VAX run URL: ${runUrl}`);
    addSummary(`## VAX evidence scan\n\nRun URL: [${runUrl}](${runUrl})\n\nFiles scanned: ${scan.scan_summary.filesScanned}\n\nAssessment continues in VAX and will not fail this CI job.`);
  } catch (error) {
    const message = error && error.stack ? error.stack : String(error);
    console.warn(`::warning::${escapeCommand(message)}`);
    addSummary(`## VAX evidence scan\n\nVAX upload did not complete, so no run URL is available.\n\nFiles scanned locally: ${scan.scan_summary.filesScanned}\n\nError:\n\n\`\`\`\n${message}\n\`\`\``);
  }
}

main().catch((error) => {
  const message = error && error.stack ? error.stack : String(error);
  if (error instanceof FatalConfigurationError) {
    setFailed(message);
    return;
  }
  console.warn(`::warning::${escapeCommand(message)}`);
  addSummary(`## VAX evidence scan\n\nThe action hit a non-fatal error before upload:\n\n\`\`\`\n${message}\n\`\`\``);
});
