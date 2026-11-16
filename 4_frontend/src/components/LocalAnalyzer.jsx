import { useEffect, useMemo, useState } from 'react';
import { analyzerAPI, scanMetricsAPI, webhookAPI } from '../api/client';
import './LocalAnalyzer.css';

const MAX_SOURCE_BYTES = 256_000;
const MAX_TOTAL_BYTES = 20_000_000;
const MAX_FILES = 1000;
const ALLOWED_EXTENSIONS = [
  '.py', '.java', '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.go', '.sql',
  '.bash', '.c', '.cc', '.conf', '.cpp', '.cs', '.css', '.dockerfile', '.h',
  '.hpp', '.html', '.ini', '.json', '.php', '.properties', '.rb', '.rs', '.sh',
  '.tf', '.toml', '.xml', '.yaml', '.yml',
];
const ALLOWED_FILENAMES = new Set([
  'dockerfile', 'makefile', 'requirements.txt', 'package.json', 'package-lock.json',
  'pom.xml', 'go.mod', 'go.sum',
]);
const EXCLUDED_DIRECTORIES = new Set([
  '.git', '.hg', '.svn', '.venv', '.next', 'venv', 'node_modules', 'vendor',
  'build', 'dist', 'target', '__pycache__', '.pytest_cache',
]);
const SECRET_FILENAMES = new Set([
  '.env', '.env.local', '.env.production', '.npmrc', '.pypirc', '.netrc',
  'id_rsa', 'id_ed25519', 'authorized_keys', 'known_hosts', 'credentials', 'secrets',
]);
const ACCEPTED_FILES = [...ALLOWED_EXTENSIONS, '.txt'].join(',');
const normalizeMetricsHistory = (scans) => scans.map((scan) => ({
  ...scan,
  ...(scan.metrics || {}),
  id: scan.id,
  scan_timestamp: scan.metrics?.scan_timestamp || scan.scanTimestamp || scan.scan_timestamp,
}));

const normalizeFilePath = (filePath) => String(filePath || '').replace(/\\/g, '/').toLowerCase();
const findingReviewKey = (scanId, index) => `${scanId}:${index}`;

const sourceContextForFinding = (finding, files) => {
  const file = files.find(
    (candidate) => normalizeFilePath(candidate.filePath) === normalizeFilePath(finding.file || finding.file_path),
  );
  const line = Number(finding.line);
  if (!file || !Number.isInteger(line) || line < 1) {
    return finding.code_snippet || null;
  }

  const lines = file.source.split(/\r\n|\r|\n/);
  const firstLine = Math.max(1, line - 3);
  const lastLine = Math.min(lines.length, line + 3);
  return lines
    .slice(firstLine - 1, lastLine)
    .map((text, index) => `${firstLine + index}: ${text}`)
    .join('\n')
    .slice(0, 2000);
};

const buildAiFixBrief = ({
  files,
  scanResults,
  findings,
  severityCounts,
  parserDiagnostics,
  scannerStatus,
  policyGate,
  reachabilityStatus,
  modelStatus,
  scanMetrics,
  scanComplete,
  scanFindingCount,
  dismissedFindingCount,
}) => {
  const severityRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const prioritizedFindings = [...findings].sort((left, right) => (
    (severityRank[String(left.severity || '').toUpperCase()] ?? 4)
      - (severityRank[String(right.severity || '').toUpperCase()] ?? 4)
    || Number(left.line || 0) - Number(right.line || 0)
  ));
  const includedFindings = prioritizedFindings.slice(0, 25).map((finding) => ({
    source: finding.source || 'unknown',
    rule_id: finding.rule_id || null,
    severity: finding.severity || 'unrated',
    priority: finding.priority || null,
    reachability: finding.reachability || 'UNKNOWN',
    file: finding.file || finding.file_path || null,
    line: finding.line != null
      && Number.isInteger(Number(finding.line))
      && Number(finding.line) > 0
      ? Number(finding.line)
      : null,
    message: finding.message || 'No description provided by the scanner.',
    evidence: sourceContextForFinding(finding, files),
  }));
  const fileResults = scanResults.map((item) => ({
    file: item.filePath,
    status: item.status || (item.error ? 'failed' : 'unknown'),
    language: item.result?.language || null,
    checks_run: item.result?.checks_run || [],
    error: item.error || null,
  }));
  const summary = {
    scan_status: scanComplete ? 'complete' : 'partial_or_incomplete',
    files_received: files.length,
    ast_parsed: fileResults.filter((item) => item.status === 'analyzed').length,
    scanner_only: fileResults.filter((item) => item.status === 'scanner_only').length,
    files_failed: fileResults.filter((item) => item.status === 'failed').length,
    finding_count: findings.length,
    scan_finding_count: scanFindingCount,
    dismissed_false_positive_count: dismissedFindingCount,
    included_finding_count: includedFindings.length,
    omitted_finding_count: Math.max(0, findings.length - includedFindings.length),
    severity_counts: severityCounts,
    parser_diagnostic_count: parserDiagnostics.length,
    scanners: scannerStatus || {},
    reachability: reachabilityStatus || { status: 'not_available' },
    policy_gate: policyGate,
    model: modelStatus,
    metrics: scanMetrics,
  };
  const nextStep = findings.length
    ? 'Review the evidence for each finding and request a minimal patch for confirmed issues only.'
    : dismissedFindingCount
      ? 'All findings from this scan were manually marked false positive. They remain in the full scan JSON; review them or restore them if needed.'
      : 'No confirmed findings were returned. Do not invent a fix; investigate parser diagnostics or run additional checks if concerns remain.';

  return {
    format: 'autoforge-ai-fix-handoff',
    format_version: 1,
    generated_at: new Date().toISOString(),
    purpose: 'Provide verified scan evidence and bounded source excerpts to an AI coding assistant.',
    summary,
    files: fileResults,
    findings: includedFindings,
    parser_diagnostics: parserDiagnostics.map((diagnostic) => ({
      file: diagnostic.file,
      line: diagnostic.line || null,
      parser_node: diagnostic.parser_node || null,
      message: diagnostic.message,
      source_line: diagnostic.code_snippet || null,
      classification: 'parser diagnostic, not a confirmed security finding',
    })),
    limitations: [
      'Uploaded code was statically inspected and was not executed.',
      'Parser diagnostics are not security findings and must not be treated as confirmed vulnerabilities.',
      'JavaScript, TypeScript, and other non-Python taint flows are not fully modeled by the AST pass; security findings depend on configured scanners.',
      'This handoff only contains the top 25 findings and short excerpts; omitted findings are counted in the summary.',
      'Generating this handoff does not call an AI service, edit files, commit, push, or merge changes.',
    ],
    recommended_next_step: nextStep,
    instructions_for_ai: [
      'Treat the listed findings and source excerpts as evidence, not proof; verify the surrounding project code before proposing a fix.',
      'Do not convert parser diagnostics into security findings.',
      'For confirmed issues, propose the smallest behavior-preserving unified diff and a focused regression test.',
      'Do not claim that any change was applied or verified. The project files have not been modified by this scan.',
    ],
  };
};

const buildAiFixPrompt = (brief) => (
  `Review this AutoForge AI-fix handoff. Verify each claim against the supplied source evidence. `
  + `Only propose a minimal patch for a confirmed finding, include a regression test, and do not claim changes were applied. `
  + `Parser diagnostics are not security findings. If there are no findings, say so and do not invent fixes.\n\n`
  + JSON.stringify(brief, null, 2)
);

const triggerDownload = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
};

const isScanCandidate = (file) => {
  const filePath = file.webkitRelativePath || file.name;
  const parts = filePath.replace(/\\/g, '/').split('/');
  const filename = parts.at(-1).toLowerCase();
  const extension = `.${filename.split('.').pop()}`;
  return !parts.slice(0, -1).some((part) => EXCLUDED_DIRECTORIES.has(part.toLowerCase()))
    && !SECRET_FILENAMES.has(filename)
    && !filename.startsWith('.env.')
    && !['secret', 'credential', 'private-key', 'service-account'].some((token) => filename.includes(token))
    && !['.pem', '.key', '.p12', '.pfx'].includes(extension)
    && (ALLOWED_FILENAMES.has(filename) || ALLOWED_EXTENSIONS.includes(extension));
};

const severityLevels = [
  ['CRITICAL', 'Critical', 'Fix immediately'],
  ['HIGH', 'High', 'Prioritize soon'],
  ['MEDIUM', 'Medium', 'Review and plan'],
  ['LOW', 'Low', 'Minor or informational'],
];

function AstEntry({ label, value }) {
  const [expanded, setExpanded] = useState(false);
  const isArray = Array.isArray(value);
  const isObject = value !== null && typeof value === 'object';
  if (!isArray && !isObject) {
    return <div className="analyzer-ast-value"><span>{label}: </span><code>{String(value)}</code></div>;
  }

  const entries = isArray
    ? value.map((entry, index) => [String(index), entry])
    : Object.entries(value).filter(([key]) => !['type', 'line'].includes(key));
  const type = isObject ? value.type : null;
  const line = isObject ? value.line : null;

  return (
    <details
      className="analyzer-ast-entry"
      open={expanded}
      onToggle={(event) => setExpanded(event.currentTarget.open)}
    >
      <summary>
        {label}: {type || (isArray ? 'list' : 'object')}
        {line ? ` (line ${line})` : ''} <span>({entries.length})</span>
      </summary>
      {expanded && (
        <div className="analyzer-ast-children">
          {entries.map(([key, entry]) => <AstEntry key={key} label={key} value={entry} />)}
        </div>
      )}
    </details>
  );
}

function ControlFlowView({ cfg }) {
  if (!cfg?.blocks?.length) {
    return <p className="analyzer-empty">Control-flow graph is available for Python files when that check is selected.</p>;
  }
  return (
    <div className="analyzer-cfg" aria-label="Control-flow graph blocks">
      {cfg.blocks.map((block) => (
        <article className="analyzer-cfg-block" key={block.id}>
          <div className="analyzer-cfg-block__heading">
            <strong>Block {block.id}</strong>
            <span>{block.kind}</span>
            {block.start_line && (
              <span>
                line {block.start_line}
                {block.end_line && block.end_line !== block.start_line ? `–${block.end_line}` : ''}
              </span>
            )}
          </div>
          <pre>{block.statements.length ? block.statements.join('\n') : '(empty)'}</pre>
          {block.successors.length > 0 && (
            <p className="analyzer-cfg-edges">
              {block.successors.map((edge) => (
                <span key={`${edge.block}-${edge.kind}`}>{edge.kind} → block {edge.block}</span>
              ))}
            </p>
          )}
        </article>
      ))}
    </div>
  );
}

function WebhookSetup() {
  const [open, setOpen] = useState(false);
  const [health, setHealth] = useState('not-checked');
  const [checking, setChecking] = useState(false);
  const [copyStatus, setCopyStatus] = useState('');
  const [healthDetail, setHealthDetail] = useState('');
  const backendBase = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8089/api';
  const endpoint = `${backendBase.replace(/\/api\/?$/, '')}/api/v1/webhooks/github`;

  const checkWebhook = async () => {
    setChecking(true);
    setHealth('checking');
    setHealthDetail('');
    try {
      const response = await webhookAPI.health();
      setHealth('ready');
      setHealthDetail(response.data.pull_request_analysis === 'configured'
        ? 'Backend receiver is ready. Pull-request analysis forwarding is configured; make sure the optional PR worker is running.'
        : 'Backend receiver is ready for dashboard scans. Pull-request analysis forwarding is not configured.');
    } catch (error) {
      setHealth(error.response?.status === 503 ? 'needs-configuration' : 'offline');
      setHealthDetail(error.response?.data?.detail || (
        error.response
          ? `Backend webhook health check returned HTTP ${error.response.status}.`
          : 'Backend webhook could not be reached at the configured API URL.'
      ));
    } finally {
      setChecking(false);
    }
  };

  const copyEndpoint = async () => {
    try {
      await navigator.clipboard.writeText(endpoint);
      setCopyStatus('Endpoint copied');
    } catch {
      setCopyStatus('Copy unavailable; select the endpoint text to copy it.');
    }
  };

  return (
    <section className="analyzer-webhook">
      <div className="analyzer-webhook__header">
        <div>
          <p className="analyzer-eyebrow">GitHub integration</p>
          <h3>Push and pull-request webhooks</h3>
          <p>Queue dashboard scans and run the PR security gate from GitHub events.</p>
        </div>
        <button
          type="button"
          className="analyzer-secondary-button"
          aria-expanded={open}
          onClick={() => setOpen((current) => !current)}
        >
          {open ? 'Hide webhook setup' : 'Webhook setup'}
        </button>
      </div>
      {open && (
        <div className="analyzer-webhook__content">
          <p>
            GitHub webhook endpoint: <code>{endpoint}</code>
          </p>
          <p>
            GitHub cannot reach a 127.0.0.1 address. First connect the repository
            in this dashboard, then expose backend port 8089 through a trusted
            HTTPS tunnel or deployment. Keep the webhook secret and GitHub token
            on the server; never enter them in this browser.
          </p>
          <ol>
            <li>Set <code>AUTOFORGE_GITHUB_WEBHOOK_SECRET</code> and a <code>GITHUB_TOKEN</code> with pull-request, commit-status, contents-read, and code-scanning permissions in the server-side <code>.env</code>. Both receivers use the same secret.</li>
            <li>Start the stack with <code>docker compose --profile github up -d --build</code>.</li>
            <li>Point a trusted HTTPS tunnel at <code>http://127.0.0.1:8089</code>, then set its public URL ending in <code>/api/v1/webhooks/github</code> in GitHub.</li>
            <li>Select the Push and Pull requests events, including opened, reopened, synchronize, and ready-for-review actions. Use the same webhook secret.</li>
            <li>Require the <code>autoforge/security-gate</code> commit status in branch protection if failed PR scans should block merging.</li>
          </ol>
          <div className="analyzer-webhook__actions">
            <button type="button" className="analyzer-secondary-button" onClick={copyEndpoint}>
              Copy local webhook endpoint
            </button>
            <button
              type="button"
              className="analyzer-secondary-button"
              onClick={checkWebhook}
              disabled={checking}
            >
              {checking ? 'Checking…' : 'Check backend webhook'}
            </button>
            <span role="status">
              {health === 'not-checked' && 'Webhook readiness has not been checked yet.'}
              {health === 'ready' && healthDetail}
              {health === 'checking' && 'Checking backend webhook…'}
              {(health === 'offline' || health === 'needs-configuration') && healthDetail}
              {copyStatus}
            </span>
          </div>
        </div>
      )}
    </section>
  );
}

const LocalAnalyzer = () => {
  const [files, setFiles] = useState([]);
  const [selectedFileId, setSelectedFileId] = useState('');
  const [scanResults, setScanResults] = useState([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [analyzerHealth, setAnalyzerHealth] = useState('checking');
  const [scanStartedAt, setScanStartedAt] = useState(null);
  const [elapsedScanSeconds, setElapsedScanSeconds] = useState(0);
  const [lastScanDurationMs, setLastScanDurationMs] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [view, setView] = useState('summary');
  const [projectFindings, setProjectFindings] = useState([]);
  const [scannerStatus, setScannerStatus] = useState(null);
  const [projectPolicyGate, setProjectPolicyGate] = useState(null);
  const [reachabilityStatus, setReachabilityStatus] = useState(null);
  const [modelStatus, setModelStatus] = useState(null);
  const [scanMetrics, setScanMetrics] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [historyError, setHistoryError] = useState('');
  const [reportBusy, setReportBusy] = useState(false);
  const [scanReviewId, setScanReviewId] = useState('');
  const [dismissedFindingKeys, setDismissedFindingKeys] = useState(() => new Set());
  const [aiFixPromptStatus, setAiFixPromptStatus] = useState('');

  const selectedFile = files.find((file) => file.id === selectedFileId) || files[0];
  const selectedResult = scanResults.find((item) => item.id === selectedFile?.id);
  const successes = scanResults.filter((item) => item.result);
  const allFindings = useMemo(() => (
    projectFindings.length
      ? projectFindings
      : scanResults.filter((item) => item.result).flatMap((item) => (
        item.result.findings.map((finding) => ({
          ...finding,
          file: item.filePath,
          source: 'AST',
          reachability: finding.reachability || 'UNKNOWN',
        }))
      ))
  ), [projectFindings, scanResults]);
  const activeFindings = useMemo(
    () => allFindings.filter(
      (_, index) => !dismissedFindingKeys.has(findingReviewKey(scanReviewId, index)),
    ),
    [allFindings, dismissedFindingKeys, scanReviewId],
  );
  const dismissedFindings = useMemo(
    () => allFindings
      .map((finding, index) => ({ finding, index }))
      .filter(({ index }) => dismissedFindingKeys.has(findingReviewKey(scanReviewId, index))),
    [allFindings, dismissedFindingKeys, scanReviewId],
  );
  const parserDiagnostics = useMemo(() => (
    successes.flatMap((item) => (item.result.diagnostics || []).map((diagnostic) => ({
      ...diagnostic,
      file: diagnostic.file || item.filePath,
    })))
  ), [successes]);
  const severityCounts = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const finding of activeFindings) {
      const severity = String(finding.severity || '').toUpperCase();
      if (Object.hasOwn(counts, severity)) counts[severity] += 1;
    }
    return counts;
  }, [activeFindings]);
  const reachabilityCounts = useMemo(() => ({
    reachable: activeFindings.filter((finding) => finding.reachability === 'REACHABLE_CODE').length,
    unreachable: activeFindings.filter((finding) => finding.reachability === 'UNREACHABLE_NOISE').length,
    unverified: activeFindings.filter((finding) => (
      !['REACHABLE_CODE', 'UNREACHABLE_NOISE'].includes(finding.reachability)
    )).length,
  }), [activeFindings]);
  const trendScans = useMemo(() => scanHistory.slice(0, 10).reverse(), [scanHistory]);
  const trendMaxFindings = Math.max(
    1,
    ...trendScans.map((scan) => scan.total_findings || 0),
  );
  const hotspotMax = Math.max(
    1,
    ...(scanMetrics?.file_hotspots || []).map((item) => item.max_risk_score || item.finding_count || 0),
  );
  const totalBytes = useMemo(
    () => files.reduce((total, file) => total + new TextEncoder().encode(file.source).length, 0),
    [files],
  );
  const totalSourceLines = useMemo(
    () => files.reduce((total, file) => total + (file.source ? file.source.split(/\r\n|\r|\n/).length : 0), 0),
    [files],
  );
  const estimatedScanSeconds = Math.max(
    10,
    Math.min(300, Math.round(30 + files.length * 0.75 + totalSourceLines / 250 + totalBytes / 100_000 * 8)),
  );

  useEffect(() => {
    let active = true;
    const checkHealth = () => {
      analyzerAPI.health()
        .then(() => {
          if (active) setAnalyzerHealth('online');
        })
        .catch(() => {
          if (active) setAnalyzerHealth('offline');
        });
    };
    checkHealth();
    const timer = window.setInterval(checkHealth, 15000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    if (!busy || !scanStartedAt) return undefined;
    const timer = window.setInterval(() => {
      setElapsedScanSeconds(Math.floor((Date.now() - scanStartedAt) / 1000));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [busy, scanStartedAt]);

  useEffect(() => {
    let active = true;
    scanMetricsAPI.getHistory()
      .then((response) => {
        if (active) setScanHistory(normalizeMetricsHistory(response.data.scans || []));
      })
      .catch(() => {
        analyzerAPI.getMetricsHistory()
          .then((response) => {
            if (active) {
              setScanHistory(normalizeMetricsHistory(response.data.scans || []));
              setHistoryError('Showing this device’s local history; backend history is unavailable.');
            }
          })
          .catch(() => {
            if (active) setHistoryError('Scan trend history is unavailable from the backend and local analyzer.');
          });
      });
    return () => {
      active = false;
    };
  }, []);

  const addFiles = async (fileList) => {
    const incoming = Array.from(fileList || []);
    if (!incoming.length) return;
    setError('');
    const nextFiles = [...files];
    const existingPaths = new Set(nextFiles.map((file) => file.filePath.toLowerCase()));
    const rejected = [];
    let skippedCount = 0;
    for (const file of incoming) {
      const filePath = file.webkitRelativePath || file.name;
      if (!isScanCandidate(file)) {
        skippedCount += 1;
        continue;
      }
      if (file.size > MAX_SOURCE_BYTES) {
        rejected.push(`${filePath} exceeds the ${MAX_SOURCE_BYTES.toLocaleString()} byte per-file limit`);
        continue;
      }
      if (existingPaths.has(filePath.toLowerCase())) {
        skippedCount += 1;
        continue;
      }
      if (nextFiles.length >= MAX_FILES) {
        rejected.push(`Only the first ${MAX_FILES} eligible files can be included in one scan`);
        break;
      }
      try {
        const source = await file.text();
        const size = new TextEncoder().encode(source).length;
        const usedBytes = nextFiles.reduce(
          (total, current) => total + new TextEncoder().encode(current.source).length,
          0,
        );
        if (usedBytes + size > MAX_TOTAL_BYTES) {
          rejected.push(`The scan reached the ${MAX_TOTAL_BYTES.toLocaleString()} byte total limit`);
          break;
        }
        nextFiles.push({ id: crypto.randomUUID(), filePath, source });
        existingPaths.add(filePath.toLowerCase());
      } catch (fileError) {
        rejected.push(`Could not read ${filePath}: ${fileError.message}`);
      }
    }
    setFiles(nextFiles);
    if (nextFiles.length && !nextFiles.some((file) => file.id === selectedFileId)) {
      setSelectedFileId(nextFiles[0].id);
    }
    setScanResults([]);
    setAiFixPromptStatus('');
    setProjectFindings([]);
    setDismissedFindingKeys(new Set());
    setScannerStatus(null);
    setProjectPolicyGate(null);
    setReachabilityStatus(null);
    setModelStatus(null);
    setScanMetrics(null);
    const messages = [];
    if (rejected.length) messages.push(rejected.join('. '));
    if (skippedCount) messages.push(`${skippedCount} unsupported, ignored, or duplicate file(s) skipped`);
    setError(messages.join('. '));
  };

  const removeFile = (id) => {
    const nextFiles = files.filter((file) => file.id !== id);
    setFiles(nextFiles);
    setAiFixPromptStatus('');
    if (selectedFileId === id) setSelectedFileId(nextFiles[0]?.id || '');
    setScanResults([]);
    setProjectFindings([]);
    setDismissedFindingKeys(new Set());
    setScannerStatus(null);
    setProjectPolicyGate(null);
    setReachabilityStatus(null);
    setModelStatus(null);
    setScanMetrics(null);
  };

  const scanAll = async () => {
    if (!files.length) {
      setError('Select one or more source files before starting a scan.');
      return;
    }
    setBusy(true);
    const startedAt = Date.now();
    setScanStartedAt(startedAt);
    setElapsedScanSeconds(0);
    setLastScanDurationMs(null);
    setAiFixPromptStatus('');
    setScanReviewId(crypto.randomUUID());
    setDismissedFindingKeys(new Set());
    setError('');
    setScanResults([]);
    setProjectFindings([]);
    setScannerStatus(null);
    setProjectPolicyGate(null);
    setReachabilityStatus(null);
    setModelStatus(null);
    setScanMetrics(null);
    setView('summary');
    try {
      const response = await analyzerAPI.analyzeProject(
        files.map(({ filePath, source }) => ({ file_path: filePath, source })),
      );
      const data = response.data;
      if (!Array.isArray(data.files) || data.files.length !== files.length) {
        throw new Error('The analyzer response did not include results for every selected file.');
      }
      const results = data.files.map((entry) => {
        const file = files.find((candidate) => candidate.filePath === entry.file_path);
        return {
          id: file?.id,
          filePath: entry.file_path,
          result: entry.result,
          error: entry.error,
          status: entry.status,
        };
      });
      setScanResults(results);
      setProjectFindings(data.findings || []);
      setScannerStatus(data.tools || {});
      setProjectPolicyGate(data.policy_gate || null);
      setReachabilityStatus(data.reachability || null);
      setModelStatus(data.model || null);
      setScanMetrics(data.metrics || null);
      if (data.metrics) {
        const metricsForBackend = { ...data.metrics };
        delete metricsForBackend.history_id;
        scanMetricsAPI.record(metricsForBackend)
          .then(() => scanMetricsAPI.getHistory())
          .then((historyResponse) => {
            setScanHistory(normalizeMetricsHistory(historyResponse.data.scans || []));
            setHistoryError('');
          })
          .catch(() => {
            setHistoryError('Latest scan is saved locally, but backend metric sync failed.');
            analyzerAPI.getMetricsHistory()
              .then((historyResponse) => setScanHistory(normalizeMetricsHistory(historyResponse.data.scans || [])))
              .catch(() => setHistoryError('Latest scan is saved locally, but backend sync and local history are unavailable.'));
          });
      }
      if (results.some((item) => item.error)
        || Object.values(data.tools || {}).some((tool) => tool.status !== 'complete')
        || data.reachability?.status === 'failed') {
        setError('Scan completed with partial results. Review file and tool statuses below.');
      }
    } catch (scanError) {
      if (scanError.response) {
        setError(scanError.response.data?.detail
          || `The live scan failed (HTTP ${scanError.response.status}). No report was generated.`);
      } else if (scanError.request) {
        setAnalyzerHealth('offline');
        setError(`Could not reach the AST analyzer at ${import.meta.env.VITE_ANALYZER_URL || '/analyzer'}. No report was generated; your selected files are unchanged.`);
      } else {
        setError(`${scanError.message || 'The live scan failed.'} No report was generated.`);
      }
    } finally {
      setLastScanDurationMs(Date.now() - startedAt);
      setScanStartedAt(null);
      setBusy(false);
    }
  };

  const dismissFinding = (index) => {
    const key = findingReviewKey(scanReviewId, index);
    setDismissedFindingKeys((current) => new Set(current).add(key));
  };

  const restoreFinding = (index) => {
    const key = findingReviewKey(scanReviewId, index);
    setDismissedFindingKeys((current) => {
      const next = new Set(current);
      next.delete(key);
      return next;
    });
  };

  const downloadSarif = () => {
    const runs = successes.flatMap((item) => item.result.sarif.runs || []);
    const report = {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs,
    };
    triggerDownload(
      new Blob([JSON.stringify(report, null, 2)], { type: 'application/sarif+json' }),
      'autoforge-scan-results.sarif',
    );
  };

  const downloadSummary = () => {
    triggerDownload(
      new Blob([JSON.stringify(aiFixBrief, null, 2)], { type: 'application/json' }),
      'autoforge-ai-fix-handoff.json',
    );
  };

  const downloadFullResults = () => {
    const report = {
      format: 'autoforge-scan-results',
      format_version: 1,
      generated_at: new Date().toISOString(),
      analysis_mode: 'static',
      summary: aiFixBrief.summary,
      files: scanResults.map((item) => ({
        file: item.filePath,
        status: item.status || (item.error ? 'failed' : 'unknown'),
        language: item.result?.language || null,
        checks_run: item.result?.checks_run || [],
        error: item.error || null,
      })),
      scanners: scannerStatus || {},
      reachability: reachabilityStatus || { status: 'not_available' },
      runtime_evidence: { status: 'not_collected' },
      policy_gate: projectPolicyGate,
      model: modelStatus,
      metrics: scanMetrics,
      findings: allFindings.map((finding, index) => ({
        ...finding,
        user_disposition: dismissedFindingKeys.has(findingReviewKey(scanReviewId, index))
          ? 'MARKED_FALSE_POSITIVE_FOR_THIS_SCAN'
          : 'ACTIVE',
        risk_score: finding.combined_risk_score ?? finding.final_score ?? null,
        risk_score_status: (
          finding.combined_risk_score != null || finding.final_score != null
            ? 'available'
            : 'not_provided_by_source'
        ),
      })),
      limitations: [
        'Reachability is based on static call-graph analysis, not observed live execution.',
        'UNREACHABLE_NOISE means no path was found in the static graph; unresolved dynamic calls may exist.',
        'Unknown and scanner-only language findings do not receive equivalent Python AST taint analysis.',
        'CPG-GNN output is file-level informational confidence, not a per-finding vulnerability probability.',
        'A missing risk score means the finding source did not provide a calibrated numeric score.',
        'Findings manually marked false positive are omitted from this handoff only; they remain in the full scan JSON and are not suppressed in future scans.',
      ],
    };
    triggerDownload(
      new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }),
      'autoforge-scan-results.json',
    );
  };

  const copyAiFixPrompt = async () => {
    try {
      await navigator.clipboard.writeText(aiFixPrompt);
      setAiFixPromptStatus('AI-fix prompt copied. Paste it into your coding assistant to review these scan results.');
    } catch (copyError) {
      setAiFixPromptStatus(
        `Could not copy the prompt: ${copyError.message || 'clipboard access was denied'}. Download the AI-fix handoff JSON instead.`,
      );
    }
  };

  const downloadExecutiveReport = async (format) => {
    if (!scanMetrics) return;
    setReportBusy(true);
    setError('');
    try {
      const response = await analyzerAPI.generateReport({
        metrics: scanMetrics,
        findings: activeFindings,
        format,
      });
      triggerDownload(response.data, `SECURITY_SUMMARY_REPORT.${format}`);
    } catch (reportError) {
      setError(reportError.response?.data?.detail || `Could not generate the ${format.toUpperCase()} report.`);
    } finally {
      setReportBusy(false);
    }
  };

  const scanComplete = Boolean(scannerStatus)
    && Object.values(scannerStatus).every((tool) => tool.status === 'complete')
    && !scanResults.some((item) => item.error)
    && reachabilityStatus?.status !== 'failed';
  const combinedGatePassed = projectPolicyGate
    ? projectPolicyGate.passed
    : successes.every((item) => item.result.policy_gate?.passed !== false);
  const gateLabel = scannerStatus && !scanComplete
    ? 'INCOMPLETE'
    : combinedGatePassed ? 'PASSED' : 'FAILED';
  const prioritySummary = useMemo(() => {
    if (!activeFindings.length) {
      if (dismissedFindings.length) {
        return `All ${dismissedFindings.length} finding${dismissedFindings.length === 1 ? ' was' : 's were'} marked false positive for this scan. The original findings remain in the full JSON export.`;
      }
      if (parserDiagnostics.length) {
        return `No confirmed security findings were returned. ${parserDiagnostics.length} parser diagnostic${parserDiagnostics.length === 1 ? '' : 's'} were reported and are not counted as vulnerabilities.`;
      }
      return scanComplete
        ? 'No findings were returned by the completed checks. This does not guarantee the project is free of vulnerabilities.'
        : 'No findings have been reported by completed checks. Review scanner status below; some checks may be incomplete or unavailable.';
    }

    const priorities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
      .filter((severity) => severityCounts[severity] > 0)
      .map((severity) => `${severityCounts[severity]} ${severity.toLowerCase()}`);
    const unclassifiedCount = activeFindings.length
      - Object.values(severityCounts).reduce((total, count) => total + count, 0);
    if (unclassifiedCount > 0) {
      priorities.push(`${unclassifiedCount} other/unrated`);
    }
    const affectedFiles = new Set(
      activeFindings
        .map((finding) => finding.file || finding.file_path)
        .filter(Boolean),
    );
    const ruleCounts = new Map();
    for (const finding of activeFindings) {
      const ruleValue = finding.rule_name || finding.title || finding.rule_id;
      const rule = ruleValue ? String(ruleValue) : '';
      if (rule) ruleCounts.set(rule, (ruleCounts.get(rule) || 0) + 1);
    }
    const mostCommonRule = [...ruleCounts.entries()]
      .sort((left, right) => right[1] - left[1])[0];
    const fileCount = affectedFiles.size || successes.length;
    const prioritiesText = priorities.length
      ? ` Severity breakdown: ${priorities.join(', ')}.`
      : ' Severity was not assigned to these findings.';
    const topRuleText = mostCommonRule
      ? ` Most common rule: ${mostCommonRule[0]} (${mostCommonRule[1]}).`
      : '';
    const recommendation = severityCounts.CRITICAL > 0 || severityCounts.HIGH > 0
      ? ' Address Critical and High findings first.'
      : ' Review the highest-severity findings first.';

    return `The scan detected ${activeFindings.length} finding${activeFindings.length === 1 ? '' : 's'} across ${fileCount} file${fileCount === 1 ? '' : 's'}.${prioritiesText}${topRuleText}${recommendation}`;
  }, [activeFindings, dismissedFindings.length, scanComplete, severityCounts, successes.length]);
  const aiFixBrief = buildAiFixBrief({
    files,
    scanResults,
    findings: activeFindings,
    severityCounts,
    parserDiagnostics,
    scannerStatus,
    policyGate: projectPolicyGate,
    reachabilityStatus,
    modelStatus,
    scanMetrics,
    scanComplete,
    scanFindingCount: allFindings.length,
    dismissedFindingCount: dismissedFindings.length,
  });
  const aiFixPrompt = buildAiFixPrompt(aiFixBrief);

  return (
    <>
      <section className="analyzer-panel" aria-labelledby="local-analyzer-title">
        <div className="analyzer-panel__header">
          <div>
            <p className="analyzer-eyebrow">Local analysis · multi-language</p>
            <h2 id="local-analyzer-title">Analyze source code</h2>
            <p>Files are read in your browser and sent only to the local analyzer on this computer.</p>
          </div>
          <span className={`analyzer-local-badge is-${analyzerHealth}`}>
            {analyzerHealth === 'checking'
              ? 'Checking analyzer…'
              : analyzerHealth === 'online'
                ? 'Analyzer online'
                : 'Analyzer offline'}
          </span>
        </div>

        <div
          className={`analyzer-dropzone ${dragging ? 'is-dragging' : ''}`}
          onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
          onDragLeave={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget)) setDragging(false);
          }}
          onDrop={(event) => {
            event.preventDefault();
            setDragging(false);
            addFiles(event.dataTransfer.files);
          }}
        >
          <strong>Drop project files here or select a whole folder</strong>
          <span>Up to {MAX_FILES} eligible files, {MAX_SOURCE_BYTES.toLocaleString()} bytes each</span>
          <label className="analyzer-file-picker">
            <span>Choose files</span>
            <input
              type="file"
              accept={ACCEPTED_FILES}
              multiple
              onChange={(event) => {
                addFiles(event.target.files);
                event.target.value = '';
              }}
            />
          </label>
          <label className="analyzer-file-picker">
            <span>Choose project folder</span>
            <input
              type="file"
              webkitdirectory=""
              directory=""
              multiple
              onChange={(event) => {
                addFiles(event.target.files);
                event.target.value = '';
              }}
            />
          </label>
          <small>
            Source and configuration files only. Dependencies/build outputs, binaries, and common secret files are skipped.
          </small>
        </div>

        <div className="analyzer-file-list" aria-label="Files selected for analysis">
          {files.map((file) => {
            const status = scanResults.find((item) => item.id === file.id);
            const modelFileScore = modelStatus?.file_scores?.find(
              (item) => normalizeFilePath(item.file) === normalizeFilePath(file.filePath),
            );
            return (
              <div className="analyzer-file-row" key={file.id}>
                <button
                  type="button"
                  className={file.id === selectedFileId ? 'is-selected' : ''}
                  onClick={() => {
                    setSelectedFileId(file.id);
                    setView('summary');
                  }}
                  disabled={busy}
                >
                  <strong>{file.filePath}</strong>
                  <span>
                    {status?.error
                      ? 'Analysis failed'
                      : status?.result
                        ? `${status.result.summary.finding_count} AST finding(s)`
                        : status?.status === 'scanner_only'
                          ? 'Static scanners only'
                          : 'Ready'}
                    {modelFileScore && (
                      <span>
                        {' · '}CPG-GNN vulnerability signal{' '}
                        {(modelFileScore.vulnerability_confidence * 100).toFixed(1)}% · experimental
                      </span>
                    )}
                  </span>
                </button>
                <button type="button" aria-label={`Remove ${file.filePath}`} onClick={() => removeFile(file.id)} disabled={busy}>Remove</button>
              </div>
            );
          })}
        </div>

        <div className="analyzer-checks">
          <strong>Enabled project checks</strong>
          <p>Python files get AST, taint/CFG, and cross-file reachability; supported JS/TS, Java, Go, Rust, and SQL files get parser checks. Semgrep p/default scans for security patterns and Checkov checks infrastructure. Some formats (such as HTML, CSS, and config files) are scanner-only, not AST-parsed. Static checks do not execute uploaded source.</p>
          <p>{modelStatus?.available
            ? `Experimental CPG-GNN file-level vulnerability signal is active (${modelStatus.model_name || 'configured encoder'}); it is not independently validated and does not change finding severity or the policy gate.`
            : 'CPG-GNN inference needs CPG_GNN_CHECKPOINT and locally available CodeBERT weights. Private GitHub repositories are not fetched by this local-folder workflow.'}</p>
        </div>
        <div className="analyzer-action-row">
          <button
            type="button"
            className="analyzer-primary-button"
            onClick={scanAll}
            disabled={busy || files.length === 0 || totalBytes > MAX_TOTAL_BYTES}
          >
            {busy ? `Scanning ${files.length} file${files.length === 1 ? '' : 's'}…` : `Scan ${files.length} file${files.length === 1 ? '' : 's'}`}
          </button>
          <span>Source is never executed. Total scan limit: {MAX_TOTAL_BYTES.toLocaleString()} bytes.</span>
        </div>
        {error && (
          <div className="analyzer-error" role="alert">
            <p>{error}</p>
            <button type="button" onClick={scanAll} disabled={busy || files.length === 0}>
              {busy ? 'Retrying scan…' : 'Retry scan'}
            </button>
          </div>
        )}
        {busy && (
          <section className="analyzer-live-scan" aria-live="polite" aria-label="Live AST scan status">
            <div className="analyzer-live-scan__orb" aria-hidden="true"><span /></div>
            <div className="analyzer-live-scan__main">
              <div className="analyzer-live-scan__headline">
                <strong>AST is doing its thing</strong>
                <span className="analyzer-live-scan__live"><i /> LIVE</span>
              </div>
              <p>Analyzing your selected source locally. Code is never executed.</p>
              <div className="analyzer-live-scan__stats">
                <div><strong>{files.length.toLocaleString()}</strong><span>files in this scan</span></div>
                <div><strong>{totalSourceLines.toLocaleString()}</strong><span>source lines sent</span></div>
                <div>
                  <strong>{Math.max(0, estimatedScanSeconds - elapsedScanSeconds) > 0
                    ? `~${Math.max(0, estimatedScanSeconds - elapsedScanSeconds)}s`
                    : 'Over estimate'}</strong>
                  <span>{Math.max(0, estimatedScanSeconds - elapsedScanSeconds) > 0 ? 'rough ETA' : 'still waiting on real results'}</span>
                </div>
                <div><strong>{elapsedScanSeconds}s</strong><span>elapsed</span></div>
              </div>
              <div className="analyzer-live-scan__track" aria-hidden="true"><span /></div>
              <small>
                ETA is an estimate from file count and source size; this analyzer does not stream per-file progress.
                {elapsedScanSeconds >= estimatedScanSeconds && ' The scan is still running—no findings are shown until the real response arrives.'}
              </small>
            </div>
          </section>
        )}

        {scanResults.length > 0 && (
          <div className="analyzer-results">
            {lastScanDurationMs !== null && (
              <p className="analyzer-scan-duration">
                Live analyzer response received in {(lastScanDurationMs / 1000).toFixed(1)}s.
                {' '}The displayed findings below came from this scan.
              </p>
            )}
            <div className="analyzer-summary">
              <div>
                <span className={`analyzer-gate analyzer-gate--${gateLabel.toLowerCase()}`}>
                  Policy {gateLabel}
                </span>
                <p>{successes.length} AST-parsed · {scanResults.filter((item) => item.status === 'scanner_only').length} scanner-only · {scanResults.filter((item) => item.error).length} failed</p>
              </div>
              <div className="analyzer-model-status">
                <strong>Reachability</strong>
                <span>{reachabilityCounts.reachable} static paths · {reachabilityCounts.unreachable} no static path · {reachabilityCounts.unverified} unknown</span>
                <small>Static call-graph estimate; live execution is not collected.</small>
              </div>
              <div className="analyzer-summary__counts">
                <strong>{activeFindings.length}</strong><span>active findings</span>
              </div>
              <div className="analyzer-model-status">
                <strong>{modelStatus?.name || 'ML model'}</strong>
                <span>{modelStatus?.available ? 'Available' : 'Unavailable'}</span>
              </div>
              <button type="button" className="analyzer-secondary-button" onClick={downloadSummary}>Download AI-fix brief</button>
              <button type="button" className="analyzer-secondary-button" onClick={downloadFullResults}>Download full JSON results</button>
              <button type="button" className="analyzer-secondary-button" onClick={downloadSarif} disabled={!successes.length}>Download SARIF</button>
              <button
                type="button"
                className="analyzer-secondary-button"
                onClick={() => downloadExecutiveReport('html')}
                disabled={!scanMetrics || reportBusy}
              >
                {reportBusy ? 'Generating report…' : 'Download HTML report'}
              </button>
              <button
                type="button"
                className="analyzer-secondary-button"
                onClick={() => downloadExecutiveReport('pdf')}
                disabled={!scanMetrics || reportBusy}
              >
                Download PDF report
              </button>
            </div>

            {scanMetrics && (
              <section className="analyzer-analytics" aria-label="Scan risk analytics">
                <div className="analyzer-analytics__metrics">
                  <article>
                    <strong>{scanMetrics.noise_reduction_pct}%</strong>
                    <span>Static no-path share</span>
                    <small>Findings with no path in the static graph; unknown findings are not counted</small>
                  </article>
                  <article>
                    <strong>{scanMetrics.ast_coverage_pct}%</strong>
                    <span>AST coverage</span>
                    <small>{scanMetrics.files_analyzed}/{scanMetrics.files_received} files parsed by AST</small>
                  </article>
                  <article>
                    <strong>{scanMetrics.reachable_findings}</strong>
                    <span>Reachable findings</span>
                    <small>{scanMetrics.unreachable_findings} unreachable · {scanMetrics.unverified_findings} unverified</small>
                  </article>
                  <article>
                    <strong>{modelStatus?.available ? 'Active' : 'Not configured'}</strong>
                    <span>CPG-GNN</span>
                    <small>{modelStatus?.files_scored || 0} file-level graph scores</small>
                  </article>
                </div>
                <div className="analyzer-analytics__grid">
                  <section className="analyzer-analytics__panel">
                    <h3>Risk trend</h3>
                    {historyError && <p className="analyzer-history-error">{historyError}</p>}
                    {trendScans.length > 0 ? (
                      <div className="analyzer-trend" aria-label="Findings across recent scans">
                        {trendScans.map((scan) => (
                          <div className="analyzer-trend__item" key={scan.id}>
                            <div className="analyzer-trend__bar">
                              <span style={{ height: `${Math.max(4, (scan.total_findings / trendMaxFindings) * 100)}%` }} />
                            </div>
                            <strong>{scan.total_findings}</strong>
                            <small>{new Date(scan.scan_timestamp).toLocaleDateString()}</small>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="analyzer-empty">Run scans to build local historical trends.</p>
                    )}
                  </section>
                  <section className="analyzer-analytics__panel">
                    <h3>File risk heatmap</h3>
                    {scanMetrics.file_hotspots?.length ? (
                      <div className="analyzer-hotspots">
                        {scanMetrics.file_hotspots.slice(0, 8).map((hotspot) => (
                          <div className="analyzer-hotspot" key={hotspot.file}>
                            <div className="analyzer-hotspot__label">
                              <code>{hotspot.file}</code>
                              <span>{hotspot.finding_count} finding(s) · risk {hotspot.max_risk_score.toFixed(1)}</span>
                            </div>
                            <div className="analyzer-hotspot__track">
                              <span style={{ width: `${Math.max(4, (hotspot.max_risk_score / hotspotMax) * 100)}%` }} />
                            </div>
                            <small>{hotspot.reachable} reachable · {hotspot.unreachable} unreachable · {hotspot.unknown} unverified</small>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="analyzer-empty">No finding hotspots in this scan.</p>
                    )}
                  </section>
                </div>
                <p className="analyzer-analytics__timestamp">
                  Scan completed {new Date(scanMetrics.scan_timestamp).toLocaleString()}
                </p>
              </section>
            )}

            <section className="analyzer-severity-summary" aria-labelledby="severity-summary-title">
              <div className="analyzer-severity-summary__header">
                <div>
                  <h3 id="severity-summary-title">Problems by severity</h3>
                  <p>
                    {parserDiagnostics.length > 0
                      ? `Counts below show confirmed security findings only. ${parserDiagnostics.length} parser diagnostic${parserDiagnostics.length === 1 ? '' : 's'} are listed separately.`
                      : 'Counts reflect detected security findings, not parser diagnostics.'}
                  </p>
                </div>
                <div className="analyzer-severity-card analyzer-severity-card--all">
                  <strong>{activeFindings.length}</strong>
                  <span>{activeFindings.length === 0 && parserDiagnostics.length > 0 ? 'Confirmed findings' : 'All problems'}</span>
                </div>
              </div>
              <div className="analyzer-severity-cards">
                {severityLevels.map(([severity, label, guidance]) => (
                  <div
                    className={`analyzer-severity-card analyzer-severity-card--${severity.toLowerCase()}`}
                    key={severity}
                  >
                    <strong>{severityCounts[severity]}</strong>
                    <span>{label}</span>
                    <small>{guidance}</small>
                  </div>
                ))}
              </div>
              <div className="analyzer-priority-summary">
                <strong>Summary</strong>
                <p>{prioritySummary}</p>
                <span>
                  Based on {activeFindings.length} active finding{activeFindings.length === 1 ? '' : 's'} from this scan.
                </span>
              </div>
            </section>

            <section className="analyzer-feedback" aria-labelledby="analyzer-feedback-title">
              <h3 id="analyzer-feedback-title">Review findings</h3>
              <p>
                Marking a false positive hides it from this scan&apos;s active results only.
                It does not change the policy gate or suppress findings in future scans.
              </p>
              {dismissedFindings.length > 0 && (
                <p role="status">
                  {dismissedFindings.length} finding{dismissedFindings.length === 1 ? ' is' : 's are'} marked
                  false positive for this scan. Original findings remain in the full JSON export.
                </p>
              )}
              {activeFindings.length === 0 ? (
                <p className="analyzer-empty">No findings need review.</p>
              ) : (
                <ul className="analyzer-feedback__list">
                  {allFindings.map((finding, index) => {
                    if (dismissedFindingKeys.has(findingReviewKey(scanReviewId, index))) {
                      return null;
                    }
                    return (
                      <li className="analyzer-feedback__item" key={findingReviewKey(scanReviewId, index)}>
                        <div>
                          <strong>{finding.rule_id || 'Finding'}</strong>
                          <span>{finding.severity || 'Unrated'} · {finding.file || 'unknown file'}:{finding.line || '?'}</span>
                          <p>{finding.message || 'No description provided.'}</p>
                          {Number.isFinite(finding.cpg_gnn_file_confidence) && (
                            <small>
                              Experimental file-level CPG-GNN vulnerability signal:{' '}
                              {(finding.cpg_gnn_file_confidence * 100).toFixed(1)}%.
                              {' '}This does not change this finding&apos;s severity or policy result.
                            </small>
                          )}
                          {finding.reachability_evidence && (
                            <small>
                              {finding.reachability}: {finding.reachability_evidence.reason}
                              {finding.reachability_evidence.call_path?.length > 0
                                ? ` Path: ${finding.reachability_evidence.call_path.join(' → ')}`
                                : ''}
                            </small>
                          )}
                        </div>
                        <div className="analyzer-feedback__actions">
                          <button type="button" onClick={() => dismissFinding(index)}>
                            Mark false positive
                          </button>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              )}
              {dismissedFindings.length > 0 && (
                <ul className="analyzer-feedback__list" aria-label="Findings marked false positive">
                  {dismissedFindings.map(({ finding, index }) => (
                    <li
                      className="analyzer-feedback__item analyzer-feedback__item--dismissed"
                      key={findingReviewKey(scanReviewId, index)}
                    >
                      <div>
                        <strong>{finding.rule_id || 'Finding'} · Marked false positive</strong>
                        <span>{finding.severity || 'Unrated'} · {finding.file || 'unknown file'}:{finding.line || '?'}</span>
                      </div>
                      <div className="analyzer-feedback__actions">
                        <button type="button" onClick={() => restoreFinding(index)}>
                          Undo
                        </button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            {parserDiagnostics.length > 0 && (
              <aside className="analyzer-diagnostics" aria-label="Parser diagnostics">
                <strong>Parser diagnostics — not confirmed security findings</strong>
                <ul>
                  {parserDiagnostics.map((diagnostic, index) => (
                    <li key={`${diagnostic.file}-${diagnostic.line}-${index}`}>
                      <code>{diagnostic.file}:{diagnostic.line || '?'}</code> {diagnostic.message}
                          {diagnostic.code_snippet && (
                            <pre className="analyzer-diagnostics__source">{diagnostic.code_snippet}</pre>
                          )}
                        </li>
                      ))}
                </ul>
              </aside>
            )}

            {selectedResult?.error && <p className="analyzer-error" role="alert">{selectedResult.error}</p>}
            <div className="analyzer-tool-status" aria-label="Static scanner status">
              {Object.entries(scannerStatus || {}).map(([name, tool]) => (
                <span className={`analyzer-tool-status__item is-${tool.status}`} key={name}>
                  <strong>{name}</strong>{tool.config ? ` (${tool.config})` : ''} {tool.status} · {tool.finding_count} finding(s)
                  {Number.isInteger(tool.files_scanned) && ` · ${tool.files_scanned} file(s) scanned`}
                  {tool.error && <small>{tool.error}</small>}
                </span>
              ))}
            </div>
            {selectedFile && (
              <>
                <p className="analyzer-selected-file">
                  Viewing <strong>{selectedFile.filePath}</strong>
                  {selectedResult?.result
                    ? ` · ${selectedResult.result.language} · ${selectedResult.result.summary.finding_count} finding(s)`
                    : ' · AST parser unavailable for this file type'}
                </p>
                <div className="analyzer-tabs" role="tablist" aria-label="Scan result views">
                  {[
                    ['summary', 'Summary'],
                    ...(selectedResult?.result ? [['cfg', 'Control flow'], ['ast', 'AST']] : []),
                  ].map(([value, label]) => (
                    <button
                      type="button"
                      role="tab"
                      aria-selected={view === value}
                      className={view === value ? 'is-active' : ''}
                      key={value}
                      onClick={() => setView(value)}
                    >
                      {label}
                    </button>
                  ))}
                </div>
                {view === 'summary' && (
                  <section className="analyzer-ai-fix-brief" aria-labelledby="ai-fix-brief-title">
                    <div className="analyzer-ai-fix-brief__header">
                      <div>
                        <h3 id="ai-fix-brief-title">AI-fix handoff</h3>
                        <p>{prioritySummary}</p>
                      </div>
                      <div className="analyzer-ai-fix-brief__actions">
                        <button type="button" className="analyzer-secondary-button" onClick={downloadSummary}>
                          Download JSON
                        </button>
                        <button type="button" className="analyzer-secondary-button" onClick={copyAiFixPrompt}>
                          Copy AI prompt
                        </button>
                      </div>
                    </div>
                    <p className="analyzer-ai-fix-brief__note">
                      The handoff includes real finding locations and short source excerpts for an AI assistant to review.
                      It does not call an AI service or edit, commit, or push your files.
                    </p>
                    {aiFixPromptStatus && <p className="analyzer-ai-fix-brief__status" role="status">{aiFixPromptStatus}</p>}
                    {activeFindings.length > 0 ? (
                      <ol className="analyzer-ai-fix-brief__findings">
                        {aiFixBrief.findings.map((finding, index) => (
                          <li key={`${finding.file}-${finding.line}-${finding.rule_id}-${index}`}>
                            <strong>{finding.severity} · {finding.rule_id || 'Finding'}</strong>
                            <code>{finding.file || 'unknown file'}:{finding.line || '?'}</code>
                            <p>{finding.message}</p>
                            {finding.evidence && <pre>{finding.evidence}</pre>}
                          </li>
                        ))}
                        {aiFixBrief.summary.omitted_finding_count > 0 && (
                          <li>{aiFixBrief.summary.omitted_finding_count} lower-priority finding(s) are omitted from this bounded AI handoff.</li>
                        )}
                      </ol>
                    ) : (
                      <p className="analyzer-empty">
                        No confirmed findings to fix were returned. Parser diagnostics below show source locations to inspect;
                        they are not proof of vulnerabilities.
                      </p>
                    )}
                    <small>Analysis status: {scanComplete ? 'complete for the configured checks' : 'partial or incomplete'} · {parserDiagnostics.length} parser diagnostic(s) · no automatic fixes applied.</small>
                  </section>
                )}
                {view === 'cfg' && selectedResult?.result && (
                  <ControlFlowView cfg={selectedResult.result.cfg} />
                )}
                {view === 'ast' && selectedResult?.result && (
                  <div className="analyzer-ast"><AstEntry label="Syntax tree" value={selectedResult.result.ast} /></div>
                )}
              </>
            )}
          </div>
        )}
      </section>
      <WebhookSetup />
    </>
  );
};

export default LocalAnalyzer;
