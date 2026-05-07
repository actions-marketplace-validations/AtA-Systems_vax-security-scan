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

const SUPPORTED_SCAN_TYPES = new Set(['asvs-l1']);

const ASVS_L1_CONTROLS = [
  {
    id: 'ASVS-L1-ARCH-01',
    category: 'Architecture',
    title: 'Security-relevant design and configuration evidence is present',
    severity: 'medium',
    passWhen: ['securityFiles'],
    recommendation: 'Add security documentation or configuration that describes authentication, authorization, data protection, and operational controls.'
  },
  {
    id: 'ASVS-L1-AUTHN-01',
    category: 'Authentication',
    title: 'Authentication mechanisms are visible in application evidence',
    severity: 'high',
    passWhen: ['authn'],
    recommendation: 'Use a standard authentication provider or framework and include the authentication entry points in the scanned evidence paths.'
  },
  {
    id: 'ASVS-L1-SESSION-01',
    category: 'Session Management',
    title: 'Session or token handling includes protective attributes',
    severity: 'high',
    passWhen: ['sessionProtection', 'managedAuth'],
    recommendation: 'Set Secure, HttpOnly, and SameSite on cookies or rely on a managed token/session provider with documented protections.'
  },
  {
    id: 'ASVS-L1-ACCESS-01',
    category: 'Access Control',
    title: 'Authorization checks are present for protected operations',
    severity: 'high',
    passWhen: ['authorization'],
    recommendation: 'Add explicit role, permission, ownership, policy, or middleware checks around protected routes and data operations.'
  },
  {
    id: 'ASVS-L1-VALIDATION-01',
    category: 'Validation',
    title: 'Request and data validation controls are present',
    severity: 'medium',
    passWhen: ['validation'],
    recommendation: 'Validate request bodies, parameters, and persisted data with schema validation, framework validators, or equivalent typed constraints.'
  },
  {
    id: 'ASVS-L1-CRYPTO-01',
    category: 'Cryptography',
    title: 'Cryptographic primitives are standard and no weak algorithms are detected',
    severity: 'high',
    failWhen: ['weakCrypto'],
    passWhen: ['crypto'],
    recommendation: 'Use platform cryptography libraries and remove MD5, SHA-1 for security decisions, DES, RC4, and hand-rolled cryptographic code.'
  },
  {
    id: 'ASVS-L1-ERRORS-LOGGING-01',
    category: 'Errors and Logging',
    title: 'Error handling or security logging is visible',
    severity: 'medium',
    passWhen: ['logging'],
    recommendation: 'Add structured error handling and security-relevant logging for authentication, authorization, and sensitive workflow failures.'
  },
  {
    id: 'ASVS-L1-DATA-01',
    category: 'Data Protection',
    title: 'Sensitive data and secrets are not hard-coded in source evidence',
    severity: 'high',
    failWhen: ['hardcodedSecret'],
    passWhen: ['secretManagement'],
    recommendation: 'Move secrets to CI or runtime secret storage and document how sensitive data is protected at rest and in transit.'
  },
  {
    id: 'ASVS-L1-COMMS-01',
    category: 'Communications',
    title: 'Transport security or secure endpoint configuration is present',
    severity: 'medium',
    failWhen: ['insecureTransport'],
    passWhen: ['transportSecurity'],
    recommendation: 'Use HTTPS endpoints, enforce TLS in deployment, and avoid insecure HTTP service URLs except for local development.'
  },
  {
    id: 'ASVS-L1-HEADERS-01',
    category: 'Headers and Browser Controls',
    title: 'Browser-facing security headers are configured',
    severity: 'medium',
    failWhen: ['wideCors'],
    passWhen: ['securityHeaders'],
    recommendation: 'Configure CSP, HSTS, X-Content-Type-Options, frame protection, and narrow CORS origins for browser-facing services.'
  },
  {
    id: 'ASVS-L1-FILES-01',
    category: 'Files and Resources',
    title: 'File upload and path handling controls are present when file handling exists',
    severity: 'medium',
    failWhen: ['unsafeFileHandling'],
    passWhen: ['fileControls'],
    recommendation: 'Validate upload type and size, store uploads outside executable paths, and normalize path operations before file access.'
  },
  {
    id: 'ASVS-L1-DEPS-01',
    category: 'Supply Chain',
    title: 'Dependency manifests or lockfiles are present for review',
    severity: 'medium',
    passWhen: ['dependencyManifest'],
    recommendation: 'Commit dependency manifests and lockfiles, and enable dependency update or vulnerability alerting for the repository.'
  }
];

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

function cleanScanTypes(value) {
  const requested = parseList(value).map((item) => item.toLowerCase());
  const supported = requested.filter((item) => SUPPORTED_SCAN_TYPES.has(item));
  return supported.length > 0 ? supported : ['asvs-l1'];
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
  const asvsSignals = new Map();
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
      addAsvsSignal(asvsSignals, 'securityFiles', relativePath, 'Security-relevant file path');
    }
    if (IMPORTANT_NAMES.has(base) || /lock$|lock\.json$|\.lock$/i.test(base)) {
      addAsvsSignal(asvsSignals, 'dependencyManifest', relativePath, 'Dependency manifest or lockfile');
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
    collectAsvsSignals(relativePath, content, asvsSignals);
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
    scan_results: buildScanResults(options.scanTypes, asvsSignals),
    scan_summary: {
      filesDiscovered: files.length,
      filesScanned: evidence.length,
      bytesIncluded,
      languages,
      manifests: manifests.slice(0, 80),
      securityFiles: securityFiles.slice(0, 80),
      localFindings: Array.from(localSignals.values()),
      scanTypes: options.scanTypes,
      unsupportedScanTypes: options.unsupportedScanTypes
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

function addAsvsSignal(signals, name, filePath, detail) {
  if (!signals.has(name)) {
    signals.set(name, []);
  }
  const entries = signals.get(name);
  if (!entries.some((entry) => entry.path === filePath && entry.detail === detail)) {
    entries.push({ path: filePath, detail });
  }
}

function collectAsvsSignals(relativePath, content, signals) {
  if (/firebase|auth0|okta|cognito|passport|nextauth|oauth|oidc|saml|login|signin|authenticate/i.test(content)) {
    addAsvsSignal(signals, 'authn', relativePath, 'Authentication provider, flow, or handler');
  }
  if (/firebase|auth0|okta|cognito|managed identity|identity provider/i.test(content)) {
    addAsvsSignal(signals, 'managedAuth', relativePath, 'Managed identity or authentication provider');
  }
  if (/HttpOnly|SameSite|Secure;|secure\s*:\s*true|sameSite|httpOnly|session.*cookie|csrf/i.test(content)) {
    addAsvsSignal(signals, 'sessionProtection', relativePath, 'Cookie, CSRF, or session protection');
  }
  if (/authorize|authorization|permission|policy|role|rbac|abac|owner_uid|ownerId|require_auth|isAdmin|middleware/i.test(content)) {
    addAsvsSignal(signals, 'authorization', relativePath, 'Authorization or ownership check');
  }
  if (/zod|joi|yup|ajv|pydantic|marshmallow|validator|validate|sanitize|escape|parameterized|prepared statement|req\.body|request\.data/i.test(content)) {
    addAsvsSignal(signals, 'validation', relativePath, 'Validation, sanitization, or parameterized input handling');
  }
  if (/crypto|bcrypt|argon2|scrypt|pbkdf2|sha256|AES-GCM|libsodium|fernet|secrets\./i.test(content)) {
    addAsvsSignal(signals, 'crypto', relativePath, 'Standard cryptography or password hashing library');
  }
  if (/\b(md5|sha1|des|rc4)\b/i.test(content)) {
    addAsvsSignal(signals, 'weakCrypto', relativePath, 'Potential weak cryptographic algorithm');
  }
  if (/logger|logging|audit|console\.(error|warn)|try\s*\{|catch\s*\(|except\s+Exception|HttpsError|raise\s+/i.test(content)) {
    addAsvsSignal(signals, 'logging', relativePath, 'Error handling or logging signal');
  }
  if (/process\.env|secrets\.|Secret Manager|secretmanager|github\.secret|GITHUB_TOKEN|VAX_KEY|api key|api_key/i.test(content)) {
    addAsvsSignal(signals, 'secretManagement', relativePath, 'Runtime or CI secret handling');
  }
  if (/(password|secret|token|api[_-]?key)\s*[:=]\s*['"][^'"]{12,}['"]/i.test(content)) {
    addAsvsSignal(signals, 'hardcodedSecret', relativePath, 'Potential hard-coded secret value');
  }
  if (/https:\/\/|Strict-Transport-Security|forceSSL|redirectToHttps|ssl|tls/i.test(content)) {
    addAsvsSignal(signals, 'transportSecurity', relativePath, 'TLS or HTTPS configuration');
  }
  if (/http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i.test(content)) {
    addAsvsSignal(signals, 'insecureTransport', relativePath, 'Non-local HTTP URL');
  }
  if (/helmet|Content-Security-Policy|Strict-Transport-Security|X-Content-Type-Options|X-Frame-Options|Referrer-Policy|Permissions-Policy/i.test(content)) {
    addAsvsSignal(signals, 'securityHeaders', relativePath, 'Security header configuration');
  }
  if (/cors\(\s*\{?[^}]*origin\s*:\s*['"]\*/i.test(content) || /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*/i.test(content)) {
    addAsvsSignal(signals, 'wideCors', relativePath, 'Wildcard CORS configuration');
  }
  if (/upload|multipart|multer|formidable|FileReader|bucket\.blob|storage\.bucket|open\(|readFile|writeFile|path\.join/i.test(content)) {
    addAsvsSignal(signals, 'fileHandling', relativePath, 'File or object storage handling');
  }
  if (/fileSize|limits\s*:|content-type|mime|basename|normalize|secure_filename|allowedExtensions|virus|malware/i.test(content)) {
    addAsvsSignal(signals, 'fileControls', relativePath, 'File validation or storage control');
  }
  if (/path\.(join|resolve)|readFile|writeFile|open\(/i.test(content) && !/normalize|basename|resolve\(/i.test(content)) {
    addAsvsSignal(signals, 'unsafeFileHandling', relativePath, 'File path operation without obvious normalization');
  }
}

function buildScanResults(scanTypes, signals) {
  const results = {};
  if (scanTypes.includes('asvs-l1')) {
    results['asvs-l1'] = buildAsvsL1Result(signals);
  }
  return results;
}

function buildAsvsL1Result(signals) {
  const controls = ASVS_L1_CONTROLS.map((control) => evaluateAsvsControl(control, signals));
  const weighted = controls.reduce((total, control) => {
    const weight = control.severity === 'high' ? 12 : 8;
    const value = control.result === 'pass' ? weight : control.result === 'partial' ? Math.round(weight * 0.55) : control.result === 'unknown' ? Math.round(weight * 0.25) : 0;
    return total + value;
  }, 0);
  const max = controls.reduce((total, control) => total + (control.severity === 'high' ? 12 : 8), 0);
  const score = Math.round((weighted / max) * 100);
  const gaps = controls.filter((control) => control.result === 'gap').length;
  const unknown = controls.filter((control) => control.result === 'unknown').length;
  return {
    id: 'asvs-l1',
    label: 'OWASP ASVS Level 1',
    version: '5.0.0',
    status: gaps > 0 ? 'needs_attention' : unknown > 3 ? 'watch' : 'pass',
    score,
    summary: `${controls.length} ASVS L1 control groups evaluated from repository evidence. ${gaps} gaps and ${unknown} unknowns require review.`,
    controls
  };
}

function evaluateAsvsControl(control, signals) {
  const failEvidence = collectSignalEvidence(signals, control.failWhen || []);
  if (failEvidence.length > 0) {
    return asvsControlResult(control, 'gap', failEvidence);
  }
  const passEvidence = collectSignalEvidence(signals, control.passWhen || []);
  if (passEvidence.length > 1) {
    return asvsControlResult(control, 'pass', passEvidence);
  }
  if (passEvidence.length === 1) {
    return asvsControlResult(control, 'partial', passEvidence);
  }
  if (control.id === 'ASVS-L1-FILES-01' && !signals.has('fileHandling')) {
    return asvsControlResult(control, 'not_applicable', []);
  }
  return asvsControlResult(control, 'unknown', []);
}

function collectSignalEvidence(signals, names) {
  const evidence = [];
  for (const name of names) {
    for (const item of signals.get(name) || []) {
      evidence.push({ signal: name, ...item });
    }
  }
  return evidence.slice(0, 12);
}

function asvsControlResult(control, result, evidence) {
  return {
    control: control.id,
    category: control.category,
    title: control.title,
    level: 'L1',
    severity: control.severity,
    result,
    evidence,
    files: Array.from(new Set(evidence.map((item) => item.path))).slice(0, 8),
    recommendation: result === 'pass' || result === 'not_applicable' ? '' : control.recommendation
  };
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
    throw new FatalConfigurationError(`Unable to request GitHub OIDC token: ${response.status} ${await response.text()}`);
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
    throw new FatalConfigurationError(`VAX upload failed: ${response.status} ${JSON.stringify(body)}`);
  }
  return body;
}

async function main() {
  const vaxKey = getInput('vax_key') || process.env.VAX_KEY;
  const endpoint = getInput('endpoint', 'https://us-central1-vax-ata-systems.cloudfunctions.net/action_start_run');
  const rawScanTypes = getInput('scan_types') || getInput('scan_levels', 'asvs-l1');
  const requestedScanTypes = parseList(rawScanTypes).map((item) => item.toLowerCase());
  const scanTypes = cleanScanTypes(rawScanTypes);
  const unsupportedScanTypes = requestedScanTypes.filter((item) => !SUPPORTED_SCAN_TYPES.has(item));
  const evidencePaths = parseList(getInput('evidence_paths', '.'));
  const maxFiles = parseNumber(getInput('max_files', '120'), 120);
  const maxBytes = parseNumber(getInput('max_bytes', '750000'), 750000);
  const maxFileBytes = parseNumber(getInput('max_file_bytes', '24000'), 24000);

  if (!vaxKey) {
    throw new FatalConfigurationError('VAX key is required. Set `with.vax_key` or env `VAX_KEY` from `${{ secrets.VAX_KEY }}`.');
  }

  const root = process.env.GITHUB_WORKSPACE || process.cwd();
  const oidcToken = await getGitHubOidcToken('vax');
  const scan = scanRepository(root, { evidencePaths, maxFiles, maxBytes, maxFileBytes, scanTypes, unsupportedScanTypes });

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
    scan_types: scanTypes,
    scan_levels: scanTypes,
    evidence: scan.evidence,
    evidence_truncated: scan.evidence_truncated,
    scan_results: scan.scan_results,
    scan_summary: scan.scan_summary
  };

  const result = await uploadRun(endpoint, payload);
  const runUrl = result.run_url;
  setOutput('run_url', runUrl);
  setOutput('run_id', result.run_id);

  console.log(`VAX run URL: ${runUrl}`);
  addSummary(`## VAX evidence scan\n\nRun URL: [${runUrl}](${runUrl})\n\nScan types: ${scanTypes.join(', ')}\n\nFiles scanned: ${scan.scan_summary.filesScanned}\n\nAssessment continues in VAX and will not fail this CI job.`);
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
