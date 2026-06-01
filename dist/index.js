const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const packageJson = require('../package.json');

const ACTION_VERSION = packageJson.version;
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

const ALL_SCAN_TYPES = ['asvs-l1', 'asvs-l2', 'wstg', 'nist-sp800-161r1-tier3', 'cmmc-level2', 'dora'];
const SUPPORTED_SCAN_TYPES = new Set(ALL_SCAN_TYPES);
const ASVS_CATALOG = loadAsvsCatalog();

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

const ASVS_L2_CONTROLS = [
  {
    id: 'ASVS-L2-ARCH-01',
    category: 'Architecture',
    title: 'Threat modeling or security architecture evidence is present',
    level: 'L2',
    severity: 'medium',
    passWhen: ['threatModel', 'securityArchitecture'],
    recommendation: 'Add threat model, abuse-case, trust-boundary, or security architecture documentation for the application.'
  },
  {
    id: 'ASVS-L2-AUTHN-01',
    category: 'Authentication',
    title: 'Stronger authentication controls such as MFA or verified identity provider policies are visible',
    level: 'L2',
    severity: 'high',
    passWhen: ['mfa', 'strongIdentityPolicy'],
    recommendation: 'Require MFA for privileged users and document identity provider password, lockout, recovery, and MFA policies.'
  },
  {
    id: 'ASVS-L2-SESSION-01',
    category: 'Session Management',
    title: 'Session expiry, refresh, revocation, or token lifetime controls are visible',
    level: 'L2',
    severity: 'high',
    passWhen: ['sessionLifetime', 'tokenRevocation'],
    recommendation: 'Configure session idle timeout, absolute timeout, refresh token rotation, and logout or revocation behavior.'
  },
  {
    id: 'ASVS-L2-ACCESS-01',
    category: 'Access Control',
    title: 'Centralized authorization policy or middleware protects sensitive operations',
    level: 'L2',
    severity: 'high',
    passWhen: ['centralizedAuthorization', 'policyAuthorization'],
    recommendation: 'Centralize authorization checks in middleware, policy objects, rules, or guard helpers and apply them consistently.'
  },
  {
    id: 'ASVS-L2-VALIDATION-01',
    category: 'Validation',
    title: 'Schema-based validation or typed request validation is used',
    level: 'L2',
    severity: 'high',
    passWhen: ['schemaValidation'],
    recommendation: 'Use schema validators such as Zod, Joi, AJV, Pydantic, Marshmallow, or framework validation for all external input.'
  },
  {
    id: 'ASVS-L2-CRYPTO-01',
    category: 'Cryptography',
    title: 'Key management and approved password hashing or encryption controls are visible',
    level: 'L2',
    severity: 'high',
    failWhen: ['weakCrypto'],
    passWhen: ['keyManagement', 'passwordHashing', 'modernEncryption'],
    recommendation: 'Use managed key storage, rotation-capable encryption, and Argon2, bcrypt, scrypt, or PBKDF2 for password hashing.'
  },
  {
    id: 'ASVS-L2-ERRORS-LOGGING-01',
    category: 'Errors and Logging',
    title: 'Audit logging exists for security-sensitive events',
    level: 'L2',
    severity: 'medium',
    passWhen: ['auditLogging'],
    recommendation: 'Record security-relevant authentication, authorization, administrative, and sensitive data access events.'
  },
  {
    id: 'ASVS-L2-DATA-01',
    category: 'Data Protection',
    title: 'Secret scanning and sensitive data handling controls are visible',
    level: 'L2',
    severity: 'high',
    failWhen: ['hardcodedSecret'],
    passWhen: ['secretScanning', 'secretManagement', 'dataClassification'],
    recommendation: 'Enable secret scanning or equivalent checks and document sensitive data handling, storage, and retention controls.'
  },
  {
    id: 'ASVS-L2-COMMS-01',
    category: 'Communications',
    title: 'TLS enforcement and production transport security policy are visible',
    level: 'L2',
    severity: 'high',
    failWhen: ['insecureTransport'],
    passWhen: ['hsts', 'tlsEnforcement'],
    recommendation: 'Enforce HTTPS/TLS in production, configure HSTS for browser clients, and avoid cleartext service dependencies.'
  },
  {
    id: 'ASVS-L2-HEADERS-01',
    category: 'Headers and Browser Controls',
    title: 'A restrictive browser security header policy is configured',
    level: 'L2',
    severity: 'medium',
    failWhen: ['wideCors'],
    passWhen: ['contentSecurityPolicy', 'securityHeaders'],
    recommendation: 'Define CSP and complementary browser headers, and restrict CORS to expected origins.'
  },
  {
    id: 'ASVS-L2-FILES-01',
    category: 'Files and Resources',
    title: 'File upload controls include type, size, path, and malware-oriented protections when file handling exists',
    level: 'L2',
    severity: 'medium',
    failWhen: ['unsafeFileHandling'],
    passWhen: ['fileControls', 'malwareFileControl'],
    recommendation: 'Add file type and size validation, normalized storage paths, malware scanning, and non-executable upload storage.'
  },
  {
    id: 'ASVS-L2-DEPS-01',
    category: 'Supply Chain',
    title: 'Dependency vulnerability automation or update policy is visible',
    level: 'L2',
    severity: 'medium',
    passWhen: ['dependencyAutomation'],
    recommendation: 'Enable Dependabot, Renovate, GitHub dependency review, or another automated dependency vulnerability workflow.'
  },
  {
    id: 'ASVS-L2-TESTING-01',
    category: 'Security Testing',
    title: 'Security tests or static analysis automation are visible',
    level: 'L2',
    severity: 'medium',
    passWhen: ['securityTesting'],
    recommendation: 'Add SAST, dependency review, secret scanning, or targeted security tests to CI.'
  }
];

const WSTG_CONTROLS = [
  {
    id: 'WSTG-INFO-01',
    category: 'Information Gathering',
    title: 'Application inventory and security-relevant documentation are visible',
    level: 'WSTG',
    severity: 'medium',
    passWhen: ['securityFiles', 'securityArchitecture', 'threatModel'],
    recommendation: 'Add application security documentation, architecture notes, or threat model evidence that identifies assets, trust boundaries, and exposed surfaces.'
  },
  {
    id: 'WSTG-CONF-01',
    category: 'Configuration and Deployment',
    title: 'Transport, headers, and deployment hardening controls are configured',
    level: 'WSTG',
    severity: 'high',
    failWhen: ['insecureTransport', 'wideCors'],
    passWhen: ['transportSecurity', 'securityHeaders', 'contentSecurityPolicy', 'tlsEnforcement'],
    recommendation: 'Configure TLS enforcement, browser security headers, restrictive CORS, and production deployment hardening for web-facing services.'
  },
  {
    id: 'WSTG-IDNT-AUTHN-01',
    category: 'Identity and Authentication',
    title: 'Authentication flows and identity provider controls are testable from repository evidence',
    level: 'WSTG',
    severity: 'high',
    passWhen: ['authn', 'managedAuth', 'mfa', 'strongIdentityPolicy'],
    recommendation: 'Include authentication routes, identity provider configuration, and tests or policy evidence for login, recovery, MFA, and account lifecycle behavior.'
  },
  {
    id: 'WSTG-SESS-01',
    category: 'Session Management',
    title: 'Session protection, lifetime, and revocation behavior are visible',
    level: 'WSTG',
    severity: 'high',
    passWhen: ['sessionProtection', 'sessionLifetime', 'tokenRevocation'],
    recommendation: 'Add explicit session cookie protections, token lifetime controls, refresh rotation, logout, and revocation behavior.'
  },
  {
    id: 'WSTG-ATHZ-01',
    category: 'Authorization',
    title: 'Authorization checks and policy enforcement are present for protected operations',
    level: 'WSTG',
    severity: 'high',
    passWhen: ['authorization', 'centralizedAuthorization', 'policyAuthorization'],
    recommendation: 'Centralize authorization checks and add evidence for role, permission, ownership, and policy enforcement on sensitive operations.'
  },
  {
    id: 'WSTG-INPV-01',
    category: 'Input Validation',
    title: 'Input validation and injection-oriented safeguards are implemented',
    level: 'WSTG',
    severity: 'high',
    passWhen: ['validation', 'schemaValidation', 'injectionProtection'],
    recommendation: 'Validate all external input with schemas or framework validators, and use parameterized database or command interfaces.'
  },
  {
    id: 'WSTG-ERRH-01',
    category: 'Error Handling and Logging',
    title: 'Error handling and security-relevant logging are visible',
    level: 'WSTG',
    severity: 'medium',
    passWhen: ['logging', 'auditLogging'],
    recommendation: 'Add structured error handling and security event logging for authentication, authorization, administrative, and sensitive-data workflows.'
  },
  {
    id: 'WSTG-CLNT-01',
    category: 'Client-side Testing',
    title: 'Client-side security controls and browser tests are represented',
    level: 'WSTG',
    severity: 'medium',
    failWhen: ['wideCors'],
    passWhen: ['contentSecurityPolicy', 'securityHeaders', 'clientSecurityTesting', 'webTestAutomation'],
    recommendation: 'Add client-side security controls such as CSP and browser tests for security-sensitive UI flows.'
  },
  {
    id: 'WSTG-APIT-01',
    category: 'API Testing',
    title: 'API validation, authorization, and security test coverage are visible',
    level: 'WSTG',
    severity: 'high',
    passWhen: ['apiSecurityTesting', 'validation', 'authorization', 'schemaValidation'],
    recommendation: 'Add API security tests covering authentication, authorization, input validation, error handling, and abuse cases.'
  },
  {
    id: 'WSTG-TOOL-01',
    category: 'Security Testing Automation',
    title: 'WSTG-aligned or dynamic web security testing automation is configured',
    level: 'WSTG',
    severity: 'medium',
    passWhen: ['dastTool', 'securityTesting', 'webTestAutomation'],
    recommendation: 'Add OWASP ZAP, DAST, browser automation, or targeted web security tests to CI for WSTG-oriented coverage.'
  }
];

const NIST_SP800_161R1_TIER3_CONTROLS = [
  {
    id: 'NIST-SP800-161R1-T3-SCRM-01',
    category: 'SCRM Governance',
    title: 'System-level supply chain risk management responsibilities and procedures are documented',
    level: 'Tier 3',
    severity: 'medium',
    passWhen: ['scrmPlan', 'securityFiles'],
    recommendation: 'Add system-level SCRM procedures, responsibilities, approval gates, or operating instructions for supplier and dependency risk decisions.'
  },
  {
    id: 'NIST-SP800-161R1-T3-SUPPLIER-01',
    category: 'Supplier Inventory',
    title: 'Critical suppliers, third-party services, or dependencies are inventoried for the system',
    level: 'Tier 3',
    severity: 'high',
    passWhen: ['supplierInventory', 'dependencyManifest'],
    recommendation: 'Maintain a system supplier and dependency inventory that identifies critical products, services, owners, and review cadence.'
  },
  {
    id: 'NIST-SP800-161R1-T3-PROVENANCE-01',
    category: 'Provenance and Integrity',
    title: 'Build, artifact, SBOM, or provenance controls are visible for system components',
    level: 'Tier 3',
    severity: 'high',
    passWhen: ['sbom', 'provenance', 'artifactIntegrity'],
    recommendation: 'Generate SBOMs or provenance attestations and verify artifact integrity with signing, checksums, or controlled release evidence.'
  },
  {
    id: 'NIST-SP800-161R1-T3-CICD-01',
    category: 'Development and Operations',
    title: 'CI/CD pipeline controls protect system changes and releases',
    level: 'Tier 3',
    severity: 'high',
    passWhen: ['cicdHardening', 'securityTesting', 'centralizedAuthorization'],
    recommendation: 'Harden CI/CD with protected branches or environments, pinned actions, least-privilege tokens, required reviews, and security checks.'
  },
  {
    id: 'NIST-SP800-161R1-T3-VULN-01',
    category: 'Vulnerability Management',
    title: 'Operational vulnerability and dependency risk monitoring is automated',
    level: 'Tier 3',
    severity: 'high',
    passWhen: ['dependencyAutomation', 'vulnerabilityManagement', 'secretScanning'],
    recommendation: 'Enable dependency vulnerability monitoring, update automation, secret scanning, and documented remediation procedures.'
  },
  {
    id: 'NIST-SP800-161R1-T3-CONFIG-01',
    category: 'Configuration Management',
    title: 'Secure configuration baselines or infrastructure-as-code controls are present',
    level: 'Tier 3',
    severity: 'medium',
    failWhen: ['insecureTransport', 'wideCors'],
    passWhen: ['configurationBaseline', 'tlsEnforcement', 'securityHeaders'],
    recommendation: 'Document secure configuration baselines and enforce them through infrastructure-as-code, policy checks, or deployment hardening.'
  },
  {
    id: 'NIST-SP800-161R1-T3-ACCESS-01',
    category: 'Access Control and Monitoring',
    title: 'Operational access control and audit logging evidence exists for system components',
    level: 'Tier 3',
    severity: 'high',
    passWhen: ['policyAuthorization', 'auditLogging', 'leastPrivilege'],
    recommendation: 'Apply least-privilege access policies and retain audit logs for administrative, deployment, supplier, and sensitive system activity.'
  },
  {
    id: 'NIST-SP800-161R1-T3-INCIDENT-01',
    category: 'Incident Response',
    title: 'Supply-chain or third-party incident response procedures are represented',
    level: 'Tier 3',
    severity: 'medium',
    passWhen: ['incidentResponse', 'auditLogging'],
    recommendation: 'Add incident response procedures covering supplier compromise, dependency compromise, credential exposure, and coordinated notification.'
  },
  {
    id: 'NIST-SP800-161R1-T3-CONTINGENCY-01',
    category: 'Contingency Planning',
    title: 'System continuity, fallback, backup, or supplier replacement planning is visible',
    level: 'Tier 3',
    severity: 'medium',
    passWhen: ['contingencyPlanning', 'backupRecovery'],
    recommendation: 'Document continuity, backup, recovery, or alternate supplier plans for critical system dependencies and services.'
  }
];

const CMMC_LEVEL2_CONTROLS = [
  {
    id: 'CMMC-L2-AC-01',
    category: 'Access Control',
    title: 'Access control policies, authorization checks, and least-privilege evidence are visible',
    level: 'Level 2',
    severity: 'high',
    passWhen: ['authorization', 'policyAuthorization', 'leastPrivilege'],
    recommendation: 'Add role, permission, ownership, and least-privilege evidence for users, administrators, service accounts, and protected operations.'
  },
  {
    id: 'CMMC-L2-IA-01',
    category: 'Identification and Authentication',
    title: 'Identity provider, MFA, and account policy controls are represented',
    level: 'Level 2',
    severity: 'high',
    passWhen: ['managedAuth', 'mfa', 'strongIdentityPolicy'],
    recommendation: 'Document identity provider policy, MFA requirements, account recovery, and lockout or conditional access controls.'
  },
  {
    id: 'CMMC-L2-AU-01',
    category: 'Audit and Accountability',
    title: 'Security event and administrative audit logging evidence exists',
    level: 'Level 2',
    severity: 'high',
    passWhen: ['auditLogging', 'logging'],
    recommendation: 'Record audit events for authentication, authorization, administrative changes, sensitive access, and security-relevant failures.'
  },
  {
    id: 'CMMC-L2-CM-01',
    category: 'Configuration Management',
    title: 'Secure baselines, change controls, or policy-as-code are present',
    level: 'Level 2',
    severity: 'medium',
    failWhen: ['insecureTransport', 'wideCors'],
    passWhen: ['configurationBaseline', 'cicdHardening', 'securityHeaders'],
    recommendation: 'Add secure configuration baselines, controlled change evidence, policy-as-code checks, and hardened deployment settings.'
  },
  {
    id: 'CMMC-L2-IR-01',
    category: 'Incident Response',
    title: 'Incident response procedures and security notification evidence are represented',
    level: 'Level 2',
    severity: 'medium',
    passWhen: ['incidentResponse', 'auditLogging'],
    recommendation: 'Document incident handling, reporting, escalation, evidence retention, and notification procedures for security events.'
  },
  {
    id: 'CMMC-L2-RA-01',
    category: 'Risk Assessment',
    title: 'Risk assessment, vulnerability monitoring, and remediation evidence are visible',
    level: 'Level 2',
    severity: 'high',
    passWhen: ['riskAssessment', 'vulnerabilityManagement', 'dependencyAutomation', 'securityTesting'],
    recommendation: 'Add risk assessment outputs, vulnerability scanning, remediation tracking, dependency monitoring, or recurring security test evidence.'
  },
  {
    id: 'CMMC-L2-CA-01',
    category: 'Security Assessment',
    title: 'Security assessment plans, SSP, POA&M, or control review artifacts are present',
    level: 'Level 2',
    severity: 'medium',
    passWhen: ['securityAssessment', 'securityPlan', 'poam'],
    recommendation: 'Maintain a system security plan, control assessment evidence, and POA&M or remediation tracking for unmet controls.'
  },
  {
    id: 'CMMC-L2-SC-01',
    category: 'System and Communications Protection',
    title: 'Boundary, transport, and cryptographic protections are configured',
    level: 'Level 2',
    severity: 'high',
    failWhen: ['insecureTransport'],
    passWhen: ['transportSecurity', 'tlsEnforcement', 'keyManagement', 'modernEncryption'],
    recommendation: 'Enforce TLS, document boundary protections, use managed keys, and apply modern encryption for protected data flows.'
  },
  {
    id: 'CMMC-L2-SI-01',
    category: 'System and Information Integrity',
    title: 'Security testing, vulnerability management, and malicious code protections are automated',
    level: 'Level 2',
    severity: 'high',
    passWhen: ['securityTesting', 'vulnerabilityManagement', 'secretScanning', 'malwareFileControl'],
    recommendation: 'Add SAST, dependency scanning, secret scanning, malware-oriented controls, and documented remediation procedures.'
  },
  {
    id: 'CMMC-L2-MP-01',
    category: 'Media Protection',
    title: 'Sensitive data handling, retention, and file/media controls are documented',
    level: 'Level 2',
    severity: 'medium',
    failWhen: ['hardcodedSecret', 'unsafeFileHandling'],
    passWhen: ['dataClassification', 'fileControls', 'secretManagement'],
    recommendation: 'Document data classification, retention, media handling, secure upload/storage controls, and secret management practices.'
  }
];

const DORA_CONTROLS = [
  {
    id: 'DORA-ICT-RISK-01',
    category: 'ICT Risk Management',
    title: 'ICT risk management responsibilities, register, or governance evidence is visible',
    level: 'DORA',
    severity: 'high',
    passWhen: ['ictRiskManagement', 'riskAssessment', 'scrmPlan'],
    recommendation: 'Document ICT risk management roles, risk registers, risk treatment, and governance procedures for critical digital services.'
  },
  {
    id: 'DORA-ICT-ASSET-01',
    category: 'ICT Asset and Dependency Inventory',
    title: 'ICT assets, systems, suppliers, or critical dependencies are inventoried',
    level: 'DORA',
    severity: 'high',
    passWhen: ['ictAssetInventory', 'supplierInventory', 'dependencyManifest'],
    recommendation: 'Maintain an inventory of ICT assets, critical systems, third-party ICT providers, and supporting software dependencies.'
  },
  {
    id: 'DORA-PROTECTION-01',
    category: 'Protection and Prevention',
    title: 'Preventive security controls protect ICT systems and data',
    level: 'DORA',
    severity: 'high',
    failWhen: ['insecureTransport', 'wideCors', 'hardcodedSecret'],
    passWhen: ['configurationBaseline', 'tlsEnforcement', 'securityHeaders', 'secretManagement', 'leastPrivilege'],
    recommendation: 'Harden ICT configurations, enforce TLS, protect secrets, restrict access, and apply baseline preventive security controls.'
  },
  {
    id: 'DORA-DETECTION-01',
    category: 'Detection',
    title: 'Monitoring, alerting, audit logging, or vulnerability detection evidence is present',
    level: 'DORA',
    severity: 'high',
    passWhen: ['monitoringAlerting', 'auditLogging', 'vulnerabilityManagement', 'securityTesting'],
    recommendation: 'Add monitoring, alerting, audit logs, vulnerability detection, and review procedures for ICT-related events.'
  },
  {
    id: 'DORA-INCIDENT-01',
    category: 'ICT Incident Management',
    title: 'ICT incident response, escalation, notification, or reporting procedures are represented',
    level: 'DORA',
    severity: 'high',
    passWhen: ['ictIncidentManagement', 'incidentResponse', 'auditLogging'],
    recommendation: 'Document ICT incident classification, escalation, communication, evidence retention, and regulatory or customer notification procedures.'
  },
  {
    id: 'DORA-RESILIENCE-TEST-01',
    category: 'Digital Operational Resilience Testing',
    title: 'Resilience, continuity, security, or recovery testing evidence is visible',
    level: 'DORA',
    severity: 'medium',
    passWhen: ['resilienceTesting', 'securityTesting', 'dastTool', 'webTestAutomation', 'apiSecurityTesting'],
    recommendation: 'Run recurring resilience, recovery, vulnerability, application security, and scenario-based tests for critical ICT-supported services.'
  },
  {
    id: 'DORA-CONTINUITY-01',
    category: 'Business Continuity and Recovery',
    title: 'Backup, recovery, continuity, or fallback plans are documented',
    level: 'DORA',
    severity: 'high',
    passWhen: ['contingencyPlanning', 'backupRecovery', 'resilienceTesting'],
    recommendation: 'Document business continuity, disaster recovery, backup restore, recovery objectives, and fallback provider procedures.'
  },
  {
    id: 'DORA-THIRD-PARTY-01',
    category: 'ICT Third-Party Risk',
    title: 'Third-party ICT provider risk and exit management evidence is present',
    level: 'DORA',
    severity: 'high',
    passWhen: ['ictThirdPartyRisk', 'supplierInventory', 'scrmPlan', 'thirdPartyExitPlan'],
    recommendation: 'Track critical ICT third-party providers, risk reviews, contractual controls, concentration risk, and exit or substitution plans.'
  },
  {
    id: 'DORA-CHANGE-01',
    category: 'Change and Release Controls',
    title: 'ICT change, release, or deployment controls protect production systems',
    level: 'DORA',
    severity: 'medium',
    passWhen: ['cicdHardening', 'configurationBaseline', 'changeManagement'],
    recommendation: 'Apply controlled change management, protected releases, environment approvals, rollback procedures, and policy checks for ICT changes.'
  },
  {
    id: 'DORA-INFO-SHARING-01',
    category: 'Information Sharing and Learning',
    title: 'Threat intelligence, post-incident learning, or security information sharing is represented',
    level: 'DORA',
    severity: 'medium',
    passWhen: ['threatIntelligence', 'postIncidentReview', 'incidentResponse'],
    recommendation: 'Capture threat intelligence, lessons learned, post-incident reviews, and structured security information sharing practices.'
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
  return supported.length > 0 ? supported : ['asvs-l1', 'asvs-l2'];
}

function parseNumber(value, fallback) {
  const parsed = Number.parseInt(String(value || ''), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function cleanStatus(value) {
  const status = String(value || 'unknown').toLowerCase();
  return ['pass', 'partial', 'gap', 'unknown', 'not_applicable'].includes(status) ? status : 'unknown';
}

function loadAsvsCatalog() {
  const catalogPath = path.join(__dirname, 'asvs-5.0.0.json');
  try {
    const parsed = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
    const requirements = Array.isArray(parsed.requirements) ? parsed.requirements : [];
    return {
      version: String(parsed.version || '5.0.0'),
      requirements: requirements.filter((item) => item && item.id && Number(item.level) <= 2)
    };
  } catch (error) {
    throw new FatalConfigurationError(`Unable to load ASVS catalog at ${catalogPath}: ${error.message}`);
  }
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function encodeArtifactBundle(payload) {
  const raw = Buffer.from(JSON.stringify(payload), 'utf8');
  const compressed = zlib.gzipSync(raw);
  return {
    content_type: 'application/json',
    encoding: 'gzip+base64',
    sha256: sha256(compressed),
    bytes: compressed.length,
    uncompressed_bytes: raw.length,
    data: compressed.toString('base64')
  };
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

  while (queue.length > 0 && discovered.length < maxFiles * 24) {
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
  const ext = path.extname(relativePath).toLowerCase();
  let score = 0;
  if (detectLanguage(relativePath)) score += 60;
  if (/src|app|lib|server|api|airflow|providers|tests/i.test(relativePath)) score += 25;
  if (/security|auth|session|login|password|oauth|oidc|jwt|csrf|cors/i.test(relativePath)) score += 35;
  if (relativePath.includes('.github/workflows/')) score += 18;
  if (IMPORTANT_NAMES.has(base)) score += 10;
  if (/lock$|lock\.json$|\.lock$/i.test(base)) score -= 20;
  if (['.md', '.txt'].includes(ext) && !/security|threat|architecture|auth/i.test(relativePath)) score -= 8;
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
  const asvsSignals = new Map();
  let bytesIncluded = 0;
  let truncated = false;

  if (options.artifactSignals) {
    mergeSignalMaps(asvsSignals, options.artifactSignals);
  }

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
    scan_results: buildScanResults(options.scanTypes, asvsSignals, options.mappedControls || []),
    scan_summary: {
      filesDiscovered: files.length,
      filesScanned: evidence.length,
      bytesIncluded,
      languages,
      manifests: manifests.slice(0, 80),
      securityFiles: securityFiles.slice(0, 80),
      scanTypes: options.scanTypes,
      unsupportedScanTypes: options.unsupportedScanTypes
    }
  };
}

function ingestArtifactPaths(root, requestedPaths, options) {
  const files = walkEvidencePaths(root, requestedPaths, options.maxFiles);
  const evidence = [];
  const signals = new Map();
  const mappedControls = [];
  let bytesIncluded = 0;
  let truncated = false;

  for (const filePath of files) {
    const relativePath = path.relative(root, filePath).replace(/\\/g, '/');
    const raw = fs.readFileSync(filePath);
    const fileHash = sha256(raw);
    const remaining = options.maxBytes - bytesIncluded;
    if (remaining <= 0) {
      truncated = true;
      break;
    }

    const maxForFile = Math.min(options.maxFileBytes, remaining);
    const content = raw.toString('utf8', 0, maxForFile);
    bytesIncluded += Buffer.byteLength(content, 'utf8');
    if (raw.length > maxForFile) truncated = true;

    const artifact = parseArtifact(content, relativePath);
    collectArtifactSignals(artifact, relativePath, signals);
    mappedControls.push(...collectArtifactControlMappings(artifact, relativePath));

    evidence.push({
      path: relativePath,
      sha256: fileHash,
      size: raw.length,
      truncated: raw.length > maxForFile,
      artifact_type: artifact.type || 'generic',
      content
    });
  }

  return {
    evidence,
    evidence_truncated: truncated,
    signals,
    mappedControls,
    summary: {
      artifactFilesDiscovered: files.length,
      artifactFilesScanned: evidence.length,
      artifactBytesIncluded: bytesIncluded,
      artifactTypes: summarizeArtifactTypes(evidence),
      mappedControls: mappedControls.length
    }
  };
}

function parseArtifact(content, relativePath) {
  try {
    const parsed = JSON.parse(content);
    return normalizeArtifact(parsed, relativePath);
  } catch {
    return normalizeArtifact({ type: artifactTypeFromPath(relativePath), content }, relativePath);
  }
}

function normalizeArtifact(value, relativePath) {
  if (Array.isArray(value)) {
    return { type: 'artifact_bundle', path: relativePath, artifacts: value.map((item) => normalizeArtifact(item, relativePath)) };
  }
  if (!value || typeof value !== 'object') {
    return { type: artifactTypeFromPath(relativePath), path: relativePath };
  }
  const type = String(value.artifact_type || value.type || artifactTypeFromPath(relativePath) || 'generic').toLowerCase();
  const artifacts = Array.isArray(value.artifacts) ? value.artifacts.map((item) => normalizeArtifact(item, relativePath)) : [];
  return { ...value, type, path: value.path || relativePath, artifacts };
}

function artifactTypeFromPath(relativePath) {
  const lower = relativePath.toLowerCase();
  if (/sbom|cyclonedx|spdx/.test(lower)) return 'sbom';
  if (/provenance|attestation|slsa|intoto|in-toto/.test(lower)) return 'provenance';
  if (/poam|plan.of.action|corrective/.test(lower)) return 'poam';
  if (/risk/.test(lower)) return 'risk_register';
  if (/incident/.test(lower)) return 'incident_response_plan';
  if (/continuity|disaster|backup|recovery|bcp/.test(lower)) return 'business_continuity_plan';
  if (/vulnerability|sast|dast|scan/.test(lower)) return 'vulnerability_scan';
  if (/validation|validator|schema|zod|joi|pydantic|marshmallow|output.encoding|escaping|xss|injection/.test(lower)) return 'validation_report';
  if (/security.test|abuse.case|api.security|wstg/.test(lower)) return 'security_test_report';
  if (/security.plan|ssp|system.security/.test(lower)) return 'security_plan';
  return 'generic';
}

function summarizeArtifactTypes(evidence) {
  const counts = {};
  for (const item of evidence) {
    const type = item.artifact_type || 'generic';
    counts[type] = (counts[type] || 0) + 1;
  }
  return counts;
}

function collectArtifactSignals(artifact, defaultPath, signals) {
  const artifacts = [artifact, ...(artifact.artifacts || [])];
  for (const item of artifacts) {
    const artifactPath = String(item.path || defaultPath);
    const type = String(item.type || 'generic').toLowerCase();
    for (const signal of artifactSignalsForType(type)) {
      addAsvsSignal(signals, signal.name, artifactPath, signal.detail, 'typed_artifact');
    }
  }
}

function artifactSignalsForType(type) {
  const map = {
    sbom: [{ name: 'sbom', detail: 'Typed SBOM artifact' }, { name: 'dependencyManifest', detail: 'Dependency inventory artifact' }],
    provenance: [{ name: 'provenance', detail: 'Typed build provenance artifact' }, { name: 'artifactIntegrity', detail: 'Artifact integrity attestation' }],
    attestation: [{ name: 'provenance', detail: 'Typed attestation artifact' }],
    security_plan: [{ name: 'securityPlan', detail: 'Typed security plan artifact' }, { name: 'securityAssessment', detail: 'Control implementation artifact' }],
    risk_register: [{ name: 'riskAssessment', detail: 'Typed risk register artifact' }],
    poam: [{ name: 'poam', detail: 'Typed POA&M artifact' }],
    incident_response_plan: [{ name: 'incidentResponse', detail: 'Typed incident response artifact' }, { name: 'ictIncidentManagement', detail: 'ICT incident response artifact' }],
    business_continuity_plan: [{ name: 'contingencyPlanning', detail: 'Typed continuity plan artifact' }, { name: 'backupRecovery', detail: 'Recovery procedure artifact' }],
    vulnerability_scan: [{ name: 'vulnerabilityManagement', detail: 'Typed vulnerability scan artifact' }, { name: 'securityTesting', detail: 'Security testing artifact' }],
    penetration_test_report: [{ name: 'securityTesting', detail: 'Typed penetration test artifact' }, { name: 'resilienceTesting', detail: 'Resilience or threat-led testing artifact' }],
    security_test_report: [{ name: 'securityTesting', detail: 'Typed security test artifact' }, { name: 'apiSecurityTesting', detail: 'Typed API security test artifact' }],
    validation_report: [{ name: 'validation', detail: 'Typed input validation artifact' }, { name: 'schemaValidation', detail: 'Typed schema validation artifact' }, { name: 'injectionProtection', detail: 'Typed injection protection artifact' }],
    output_encoding: [{ name: 'injectionProtection', detail: 'Typed output encoding or escaping artifact' }, { name: 'clientSecurityTesting', detail: 'Typed browser/client injection protection artifact' }],
    policy: [{ name: 'policyAuthorization', detail: 'Typed policy artifact' }],
    access_review: [{ name: 'leastPrivilege', detail: 'Typed access review artifact' }]
  };
  return map[type] || [];
}

function collectArtifactControlMappings(artifact, defaultPath) {
  const mappings = [];
  const artifacts = [artifact, ...(artifact.artifacts || [])];
  for (const item of artifacts) {
    const controls = []
      .concat(Array.isArray(item.controls) ? item.controls : [])
      .concat(Array.isArray(item.control_mappings) ? item.control_mappings : []);
    for (const mapping of controls) {
      const normalized = normalizeControlMapping(mapping, item, defaultPath);
      if (normalized) mappings.push(normalized);
    }
  }
  return mappings;
}

function normalizeControlMapping(mapping, artifact, defaultPath) {
  if (!mapping || typeof mapping !== 'object') return null;
  const controlId = String(mapping.control || mapping.control_id || mapping.id || '').trim();
  if (!controlId) return null;
  const framework = String(mapping.framework || '').trim();
  const scanType = String(mapping.scan_type || scanTypeForFramework(framework) || '').toLowerCase();
  const evidencePath = String(mapping.path || artifact.path || defaultPath);
  const detail = String(mapping.detail || mapping.evidence || artifact.title || `Explicit mapping from ${artifact.type || 'artifact'} artifact`);
  return {
    scan_type: scanType || 'artifact-mapping',
    framework,
    control: controlId,
    category: mapping.category || artifact.type || 'Artifact Evidence',
    title: mapping.title || controlId,
    level: mapping.level,
    severity: String(mapping.severity || 'medium').toLowerCase(),
    result: cleanStatus(mapping.status || mapping.result || 'pass'),
    evidence: [{ signal: 'artifact_mapping', path: evidencePath, detail, source: 'typed_artifact' }],
    files: [evidencePath],
    recommendation: mapping.recommendation || ''
  };
}

function scanTypeForFramework(framework) {
  const value = String(framework || '').toLowerCase();
  if (value.includes('dora')) return 'dora';
  if (value.includes('cmmc')) return 'cmmc-level2';
  if (value.includes('nist')) return 'nist-sp800-161r1-tier3';
  if (value.includes('wstg')) return 'wstg';
  if (value.includes('asvs') && value.includes('l2')) return 'asvs-l2';
  if (value.includes('asvs')) return 'asvs-l1';
  return '';
}

function mergeSignalMaps(target, source) {
  for (const [name, entries] of source.entries()) {
    for (const entry of entries) {
      addAsvsSignal(target, name, entry.path, entry.detail, entry.source);
    }
  }
}

function addAsvsSignal(signals, name, filePath, detail, source = 'repository_evidence') {
  if (!signals.has(name)) {
    signals.set(name, []);
  }
  const entries = signals.get(name);
  if (!entries.some((entry) => entry.path === filePath && entry.detail === detail)) {
    entries.push({ path: filePath, detail, source });
  }
}

function buildScanResults(scanTypes, signals, mappedControls = []) {
  const results = {};
  if (scanTypes.includes('asvs-l1')) {
    results['asvs-l1'] = buildAsvsRequirementResult('asvs-l1', 'OWASP ASVS Level 1', ASVS_CATALOG.requirements.filter((control) => Number(control.level) <= 1), signals);
  }
  if (scanTypes.includes('asvs-l2')) {
    results['asvs-l2'] = buildAsvsRequirementResult('asvs-l2', 'OWASP ASVS Level 2', ASVS_CATALOG.requirements.filter((control) => Number(control.level) <= 2), signals);
  }
  if (scanTypes.includes('wstg')) {
    results.wstg = buildAsvsResult('wstg', 'OWASP WSTG', WSTG_CONTROLS, signals, 'repository-evidence');
  }
  if (scanTypes.includes('nist-sp800-161r1-tier3')) {
    results['nist-sp800-161r1-tier3'] = buildAsvsResult(
      'nist-sp800-161r1-tier3',
      'NIST SP 800-161 Rev. 1 Tier 3',
      NIST_SP800_161R1_TIER3_CONTROLS,
      signals,
      'Rev. 1'
    );
  }
  if (scanTypes.includes('cmmc-level2')) {
    results['cmmc-level2'] = buildAsvsResult(
      'cmmc-level2',
      'CMMC Level 2',
      CMMC_LEVEL2_CONTROLS,
      signals,
      '2.0'
    );
  }
  if (scanTypes.includes('dora')) {
    results.dora = buildAsvsResult('dora', 'DORA', DORA_CONTROLS, signals, 'EU 2022/2554');
  }
  return mergeMappedControls(results, mappedControls);
}

function buildAsvsRequirementResult(id, label, requirements, signals) {
  const controls = requirements.map((requirement) => evaluateAsvsRequirement(requirement, signals));
  return {
    id,
    label,
    framework: 'OWASP ASVS',
    version: ASVS_CATALOG.version,
    status: 'pending',
    score: null,
    summary: `${controls.length} ${label} v${ASVS_CATALOG.version} requirements queued for assessment from uploaded repository evidence.`,
    controls
  };
}

function evaluateAsvsRequirement(requirement, signals) {
  const evidence = collectSignalEvidence(signals, signalNamesForAsvsRequirement(requirement));
  return asvsRequirementResult(requirement, 'pending', evidence, 'Awaiting assessment against uploaded repository evidence.');
}

function asvsRequirementResult(requirement, result, evidence, rationale) {
  return {
    control: requirement.id,
    framework: 'OWASP ASVS',
    standard_id: requirement.req_id,
    category: requirement.section_name || requirement.chapter_name,
    title: requirement.description,
    requirement: requirement.description,
    level: `L${requirement.level}`,
    severity: Number(requirement.level) <= 1 ? 'high' : 'medium',
    result,
    evidence,
    evidence_source: evidence.length > 0 ? 'typed_artifact' : 'uploaded_repository',
    assessment_source: 'pending_assessment',
    rationale,
    files: Array.from(new Set(evidence.map((item) => item.path))).slice(0, 8),
    recommendation: `Assess OWASP ASVS ${requirement.req_id}: ${requirement.description}`
  };
}

function signalNamesForAsvsRequirement(requirement) {
  const text = `${requirement.chapter_name || ''} ${requirement.section_name || ''} ${requirement.description || ''}`.toLowerCase();
  const names = new Set();
  const add = (...items) => items.forEach((item) => names.add(item));

  if (/encode|escape|injection|sanitize|xss|sql|query|command|ldap|xpath|ssrf|template|deserial|xml|xxe|regex|redos/.test(text)) add('validation', 'injectionProtection', 'schemaValidation', 'clientSecurityTesting');
  if (/business logic|transaction|workflow|sequence|limit|quota|anti-automation|rate limit|dos|denial/.test(text)) add('validation', 'rateLimit', 'securityTesting', 'apiSecurityTesting');
  if (/browser|content-security-policy|csp|hsts|cors|cross-origin|csrf|sec-fetch|frame|referrer|cookie|dom|jsonp|redirect/.test(text)) add('securityHeaders', 'contentSecurityPolicy', 'hsts', 'sessionProtection', 'webTestAutomation');
  if (/api|web service|content-type|http method|header|graphql|websocket|message/.test(text)) add('validation', 'apiSecurityTesting', 'transportSecurity', 'securityHeaders');
  if (/file|upload|download|archive|zip|path|malware|antivirus|content-disposition/.test(text)) add('fileHandling', 'fileControls', 'malwareFileControl');
  if (/authenticat|credential|password|mfa|multi-factor|passkey|webauthn|account|lockout|recovery/.test(text)) add('authn', 'managedAuth', 'mfa', 'strongIdentityPolicy');
  if (/session|logout|cookie|csrf|token lifetime|idle|absolute|revocation/.test(text)) add('sessionProtection', 'sessionLifetime', 'tokenRevocation');
  if (/authori|access control|permission|role|policy|tenant|object|ownership|least privilege/.test(text)) add('authorization', 'centralizedAuthorization', 'policyAuthorization', 'leastPrivilege');
  if (/jwt|token|claim|signature|jws|jwe/.test(text)) add('crypto', 'keyManagement', 'tokenRevocation');
  if (/oauth|oidc|openid|client secret|redirect uri|pkce|scope/.test(text)) add('authn', 'managedAuth', 'strongIdentityPolicy', 'transportSecurity');
  if (/crypto|encrypt|key|random|secret|hash|argon2|bcrypt|scrypt|pbkdf|certificate/.test(text)) add('crypto', 'keyManagement', 'modernEncryption', 'passwordHashing', 'secretManagement');
  if (/tls|https|transport|certificate|strict-transport/.test(text)) add('transportSecurity', 'hsts', 'tlsEnforcement');
  if (/configuration|debug|environment|dependency|component|supply|version|hardening/.test(text)) add('securityFiles', 'dependencyManifest', 'dependencyAutomation', 'cicdHardening');
  if (/data protection|sensitive|privacy|pii|retention|classification|secret/.test(text)) add('secretManagement', 'secretScanning', 'dataClassification');
  if (/architecture|secure coding|threat model|design|trust boundary/.test(text)) add('securityArchitecture', 'threatModel', 'securityFiles');
  if (/log|error|exception|audit|monitor/.test(text)) add('logging', 'auditLogging', 'monitoringAlerting');
  if (/test|scan|vulnerab|sast|dast|penetration/.test(text)) add('securityTesting', 'dastTool', 'webTestAutomation', 'apiSecurityTesting');
  if (/webrtc|signaling/.test(text)) add('transportSecurity', 'validation', 'authn');
  if (names.size === 0) add('securityFiles');
  return Array.from(names);
}

function mergeMappedControls(results, mappedControls) {
  const touched = new Set();
  for (const control of mappedControls) {
    const scanType = control.scan_type || 'artifact-mapping';
    touched.add(scanType);
    if (!results[scanType]) {
      results[scanType] = {
        id: scanType,
        label: control.framework || 'Typed artifact mappings',
        version: 'artifact-mapping',
        status: 'pass',
        score: 100,
        summary: 'Controls mapped explicitly from typed artifacts.',
        controls: []
      };
    }
    const controls = results[scanType].controls;
    const existingIndex = controls.findIndex((item) => item.control === control.control);
    if (existingIndex >= 0) {
      controls[existingIndex] = { ...controls[existingIndex], ...control };
    } else {
      controls.push(control);
    }
  }
  for (const scanType of touched) {
    refreshResultSummary(results[scanType]);
  }
  return results;
}

function refreshResultSummary(result) {
  const controls = result.controls || [];
  if (controls.length === 0) return;
  const weighted = controls.reduce((total, control) => {
    const weight = control.severity === 'high' ? 12 : 8;
    const value = control.result === 'pass' ? weight : control.result === 'partial' ? Math.round(weight * 0.55) : control.result === 'unknown' ? Math.round(weight * 0.25) : 0;
    return total + value;
  }, 0);
  const max = controls.reduce((total, control) => total + (control.severity === 'high' ? 12 : 8), 0);
  const gaps = controls.filter((control) => control.result === 'gap').length;
  const unknown = controls.filter((control) => control.result === 'unknown').length;
  result.score = Math.round((weighted / max) * 100);
  result.status = gaps > 0 ? 'needs_attention' : unknown > 3 ? 'watch' : 'pass';
  result.summary = `${controls.length} ${result.label || result.id} control groups evaluated from repository and typed artifact evidence. ${gaps} gaps and ${unknown} controls need additional evidence.`;
}

function buildAsvsResult(id, label, controlDefinitions, signals, version = '5.0.0') {
  const controls = controlDefinitions.map((control) => evaluateAsvsControl(control, signals));
  return {
    id,
    label,
    version,
    status: 'pending',
    score: null,
    summary: `${controls.length} ${label} control groups queued for assessment from uploaded repository evidence.`,
    controls
  };
}

function evaluateAsvsControl(control, signals) {
  const passEvidence = collectSignalEvidence(signals, control.passWhen || []);
  return asvsControlResult(control, 'pending', passEvidence);
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
    level: control.level || 'L1',
    severity: control.severity,
    result,
    evidence,
    evidence_source: evidence.length > 0 ? 'typed_artifact' : 'uploaded_repository',
    assessment_source: 'pending_assessment',
    rationale: 'Awaiting assessment against uploaded repository evidence.',
    files: Array.from(new Set(evidence.map((item) => item.path))).slice(0, 8),
    recommendation: control.recommendation
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
  const scanTypes = ALL_SCAN_TYPES;
  const unsupportedScanTypes = [];
  const evidencePaths = parseList(getInput('evidence_paths', '.'));
  const artifactPaths = parseList(getInput('artifact_paths', '.vax'));
  const maxFiles = parseNumber(getInput('max_files', '1000'), 1000);
  const maxBytes = parseNumber(getInput('max_bytes', '8000000'), 8000000);
  const maxFileBytes = parseNumber(getInput('max_file_bytes', '40000'), 40000);

  if (!vaxKey) {
    throw new FatalConfigurationError('VAX key is required. Set `with.vax_key` or env `VAX_KEY` from `${{ secrets.VAX_KEY }}`.');
  }

  const root = process.env.GITHUB_WORKSPACE || process.cwd();
  const oidcToken = await getGitHubOidcToken('vax');
  const artifacts = artifactPaths.length > 0
    ? ingestArtifactPaths(root, artifactPaths, { maxFiles, maxBytes, maxFileBytes })
    : { evidence: [], evidence_truncated: false, signals: new Map(), mappedControls: [], summary: {} };
  const scan = scanRepository(root, {
    evidencePaths,
    maxFiles,
    maxBytes,
    maxFileBytes,
    scanTypes,
    unsupportedScanTypes,
    artifactSignals: artifacts.signals,
    mappedControls: artifacts.mappedControls
  });

  const evidence = scan.evidence.concat(artifacts.evidence);
  const scanResults = scan.scan_results;
  const artifactBundle = encodeArtifactBundle({
    evidence,
    scan_results: scanResults
  });

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
    artifact_paths: artifactPaths,
    artifact_bundle: artifactBundle,
    evidence_truncated: scan.evidence_truncated || artifacts.evidence_truncated,
    scan_summary: { ...scan.scan_summary, ...artifacts.summary }
  };

  const result = await uploadRun(endpoint, payload);
  const runUrl = result.run_url;
  const configuredScanTypes = Array.isArray(result.scan_types) && result.scan_types.length > 0 ? result.scan_types : scanTypes;
  setOutput('run_url', runUrl);
  setOutput('run_id', result.run_id);

  console.log(`VAX run URL: ${runUrl}`);
  addSummary(`## VAX evidence scan\n\nRun URL: [${runUrl}](${runUrl})\n\nConfigured scan types: ${configuredScanTypes.join(', ')}\n\nFiles scanned: ${scan.scan_summary.filesScanned}\n\nArtifacts scanned: ${artifacts.summary.artifactFilesScanned || 0}\n\nAssessment continues in VAX and will not fail this CI job.`);
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
