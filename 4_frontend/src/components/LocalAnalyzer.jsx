import { useMemo, useState } from 'react';
import { analyzerAPI } from '../api/client';

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
  '.git', '.hg', '.svn', '.venv', 'venv', 'node_modules', 'vendor',
  'build', 'dist', 'target', '__pycache__', '.pytest_cache',
]);
const SECRET_FILENAMES = new Set([
  '.env', '.env.local', '.env.production', '.npmrc', '.pypirc', '.netrc',
  'id_rsa', 'id_ed25519', 'authorized_keys', 'known_hosts', 'credentials', 'secrets',
]);
const ACCEPTED_FILES = [...ALLOWED_EXTENSIONS, '.txt'].join(',');
const severityClass = (severity) =>
  `analyzer-severity analyzer-severity--${severity.toLowerCase()}`;

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

const severityRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

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

function ControlFlowView({ cfg, onSelectLine }) {
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
              <button type="button" onClick={() => onSelectLine(block.start_line)}>
                line {block.start_line}
                {block.end_line && block.end_line !== block.start_line ? `–${block.end_line}` : ''}
              </button>
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
  const endpoint = 'http://127.0.0.1:8091/api/v1/github/events';

  const checkWebhook = async () => {
    setChecking(true);
    setHealth('checking');
    try {
      await analyzerAPI.webhookHealth();
      setHealth('ready');
    } catch (error) {
      setHealth(error.response?.status === 503 ? 'needs-configuration' : 'offline');
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
          <h3>Pull request webhooks</h3>
          <p>Set up authenticated pull-request events for the local pipeline.</p>
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
            Local endpoint: <code>{endpoint}</code>
          </p>
          <p>
            GitHub cannot reach a 127.0.0.1 address. For a real GitHub delivery,
            expose this service through a trusted HTTPS tunnel or deploy it; never
            put the webhook secret in this browser.
          </p>
          <ol>
            <li>Start the configured webhook service on port 8091.</li>
            <li>Set <code>WEBHOOK_SECRET</code> and <code>GITHUB_REPOSITORY</code> in its environment.</li>
            <li>In GitHub, add the HTTPS public URL ending in <code>/api/v1/github/events</code>.</li>
            <li>Choose the Pull requests event and use the same secret; enable opened, reopened, and synchronize actions.</li>
          </ol>
          <div className="analyzer-webhook__actions">
            <button type="button" className="analyzer-secondary-button" onClick={copyEndpoint}>
              Copy local endpoint
            </button>
            <button
              type="button"
              className="analyzer-secondary-button"
              onClick={checkWebhook}
              disabled={checking}
            >
              {checking ? 'Checking…' : 'Check local webhook'}
            </button>
            <span role="status">
              {health === 'ready' && 'Webhook service is configured.'}
              {health === 'checking' && 'Checking webhook service…'}
              {health === 'offline' && 'Webhook service is not running on port 8091.'}
              {health === 'needs-configuration' && 'Service is running, but its secret or repository is not configured.'}
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
  const [dragging, setDragging] = useState(false);
  const [selectedLine, setSelectedLine] = useState(null);
  const [view, setView] = useState('findings');
  const [projectFindings, setProjectFindings] = useState([]);
  const [scannerStatus, setScannerStatus] = useState(null);
  const [projectPolicyGate, setProjectPolicyGate] = useState(null);
  const [reachabilityStatus, setReachabilityStatus] = useState(null);
  const [modelStatus, setModelStatus] = useState(null);
  const [reachabilityFilter, setReachabilityFilter] = useState('all');
  const [severitySort, setSeveritySort] = useState('highest');
  const [findingScope, setFindingScope] = useState('file');

  const selectedFile = files.find((file) => file.id === selectedFileId) || files[0];
  const selectedResult = scanResults.find((item) => item.id === selectedFile?.id);
  const sourceLines = (selectedFile?.source || '').split(/\r?\n/);
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
  const scopedFindings = findingScope === 'file' && selectedFile
    ? allFindings.filter((finding) => (
      (finding.file || finding.file_path) === selectedFile.filePath
    ))
    : allFindings;
  const visibleFindings = scopedFindings
    .filter((finding) => (
      reachabilityFilter === 'all'
      || (reachabilityFilter === 'unverified'
        ? !['REACHABLE_CODE', 'UNREACHABLE_NOISE'].includes(finding.reachability)
        : finding.reachability === reachabilityFilter)
    ))
    .sort((left, right) => {
      const severityOrder = (severityRank[left.severity] ?? 5) - (severityRank[right.severity] ?? 5);
      if (severityOrder !== 0) return severitySort === 'highest' ? severityOrder : -severityOrder;
      return String(left.file || '').localeCompare(String(right.file || ''))
        || Number(left.line || 0) - Number(right.line || 0);
    });
  const severityCounts = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const finding of allFindings) {
      if (Object.hasOwn(counts, finding.severity)) counts[finding.severity] += 1;
    }
    return counts;
  }, [allFindings]);
  const reachabilityCounts = useMemo(() => ({
    reachable: allFindings.filter((finding) => finding.reachability === 'REACHABLE_CODE').length,
    unreachable: allFindings.filter((finding) => finding.reachability === 'UNREACHABLE_NOISE').length,
    unverified: allFindings.filter((finding) => (
      !['REACHABLE_CODE', 'UNREACHABLE_NOISE'].includes(finding.reachability)
    )).length,
  }), [allFindings]);
  const totalBytes = files.reduce(
    (total, file) => total + new TextEncoder().encode(file.source).length,
    0,
  );

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
    setProjectFindings([]);
    setScannerStatus(null);
    setProjectPolicyGate(null);
    setReachabilityStatus(null);
    setModelStatus(null);
    setFindingScope('file');
    const messages = [];
    if (rejected.length) messages.push(rejected.join('. '));
    if (skippedCount) messages.push(`${skippedCount} unsupported, ignored, or duplicate file(s) skipped`);
    setError(messages.join('. '));
  };

  const removeFile = (id) => {
    const nextFiles = files.filter((file) => file.id !== id);
    setFiles(nextFiles);
    if (selectedFileId === id) setSelectedFileId(nextFiles[0]?.id || '');
    setScanResults([]);
    setProjectFindings([]);
    setScannerStatus(null);
    setProjectPolicyGate(null);
    setReachabilityStatus(null);
    setModelStatus(null);
    setFindingScope('file');
  };

  const scanAll = async () => {
    setBusy(true);
    setError('');
    setScanResults([]);
    setProjectFindings([]);
    setScannerStatus(null);
    setProjectPolicyGate(null);
    setReachabilityStatus(null);
    setModelStatus(null);
    setFindingScope('file');
    setSelectedLine(null);
    try {
      const response = await analyzerAPI.analyzeProject(
        files.map(({ filePath, source }) => ({ file_path: filePath, source })),
      );
      const data = response.data;
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
      if (results.some((item) => item.error)
        || Object.values(data.tools || {}).some((tool) => tool.status !== 'complete')
        || data.reachability?.status === 'failed') {
        setError('Scan completed with partial results. Review file and tool statuses below.');
      }
    } catch (scanError) {
      setError(scanError.response?.data?.detail
        || 'Could not reach the local analyzer. Start it on 127.0.0.1:8090 and retry.');
    } finally {
      setBusy(false);
    }
  };

  const downloadSarif = () => {
    const runs = successes.flatMap((item) => item.result.sarif.runs || []);
    const report = {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/sarif+json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'autoforge-scan-results.sarif';
    link.click();
    URL.revokeObjectURL(url);
  };

  const downloadSummary = () => {
    const report = {
      scanned_files: successes.map((item) => ({
        file: item.filePath,
        language: item.result.language,
        checks_run: item.result.checks_run,
        findings: item.result.findings,
      })),
      failed_files: scanResults.filter((item) => item.error).map(({ filePath, error: reason }) => ({
        file: filePath,
        error: reason,
      })),
      summary: {
        files_scanned: successes.length,
        findings: allFindings.length,
        severity_counts: severityCounts,
        reachability: reachabilityCounts,
        scanners: scannerStatus,
        policy_gate: projectPolicyGate,
        reachability_status: reachabilityStatus,
        model: modelStatus,
      },
      findings: allFindings,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'autoforge-scan-summary.json';
    link.click();
    URL.revokeObjectURL(url);
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

  return (
    <>
      <section className="analyzer-panel" aria-labelledby="local-analyzer-title">
        <div className="analyzer-panel__header">
          <div>
            <p className="analyzer-eyebrow">Local analysis · multi-language</p>
            <h2 id="local-analyzer-title">Analyze source code</h2>
            <p>Files are read in your browser and sent only to the local analyzer on this computer.</p>
          </div>
          <span className="analyzer-local-badge">Loopback analyzer</span>
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
            return (
              <div className="analyzer-file-row" key={file.id}>
                <button
                  type="button"
                  className={file.id === selectedFileId ? 'is-selected' : ''}
                  onClick={() => {
                    setSelectedFileId(file.id);
                    setFindingScope('file');
                    setSelectedLine(null);
                    setView('findings');
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
                  </span>
                </button>
                <button type="button" aria-label={`Remove ${file.filePath}`} onClick={() => removeFile(file.id)} disabled={busy}>Remove</button>
              </div>
            );
          })}
        </div>

        <div className="analyzer-checks">
          <strong>Enabled project checks</strong>
          <p>AST and Python taint/CFG, cross-file Python reachability, Semgrep, and Checkov. Static checks do not execute uploaded source.</p>
          <p>ML inference is reported as unavailable unless a trained checkpoint is installed. Private GitHub repositories are not fetched by this local-folder workflow.</p>
        </div>
        <div className="analyzer-action-row">
          <button
            type="button"
            className="analyzer-primary-button"
            onClick={scanAll}
            disabled={busy || files.length === 0 || totalBytes > MAX_TOTAL_BYTES}
          >
            {busy ? `Scanning ${files.length} files…` : `Scan ${files.length} file${files.length === 1 ? '' : 's'}`}
          </button>
          <span>Source is never executed. Total scan limit: {MAX_TOTAL_BYTES.toLocaleString()} bytes.</span>
        </div>
        {error && <p className="analyzer-error" role="alert">{error}</p>}

        {scanResults.length > 0 && (
          <div className="analyzer-results">
            <div className="analyzer-summary">
              <div>
                <span className={`analyzer-gate analyzer-gate--${gateLabel.toLowerCase()}`}>
                  Policy {gateLabel}
                </span>
                <p>{successes.length} AST-parsed, {scanResults.filter((item) => item.status === 'scanner_only').length} scanner-only, {scanResults.filter((item) => item.error).length} failed · {severityCounts.CRITICAL} critical, {severityCounts.HIGH} high, {severityCounts.MEDIUM} medium, {severityCounts.LOW} low</p>
              </div>
              <div className="analyzer-model-status">
                <strong>Reachability</strong>
                <span>{reachabilityCounts.reachable} reachable · {reachabilityCounts.unreachable} unreachable · {reachabilityCounts.unverified} unverified</span>
              </div>
              <div className="analyzer-summary__counts">
                <strong>{allFindings.length}</strong><span>total findings</span>
              </div>
              <div className="analyzer-model-status">
                <strong>{modelStatus?.name || 'ML model'}</strong>
                <span>{modelStatus?.available ? 'Available' : 'Unavailable'}</span>
              </div>
              <button type="button" className="analyzer-secondary-button" onClick={downloadSummary}>Download summary</button>
              <button type="button" className="analyzer-secondary-button" onClick={downloadSarif} disabled={!successes.length}>Download SARIF</button>
            </div>

            {selectedResult?.error && <p className="analyzer-error" role="alert">{selectedResult.error}</p>}
            <div className="analyzer-tool-status" aria-label="Static scanner status">
              {Object.entries(scannerStatus || {}).map(([name, tool]) => (
                <span className={`analyzer-tool-status__item is-${tool.status}`} key={name}>
                  <strong>{name}</strong> {tool.status} · {tool.finding_count} finding(s)
                  {tool.error && <small>{tool.error}</small>}
                </span>
              ))}
            </div>
            {selectedFile && (
              <>
                <p className="analyzer-selected-file">
                  Viewing <strong>{selectedFile.filePath}</strong>
                  {selectedResult?.result
                    ? ` · ${selectedResult.result.language} · checks: ${selectedResult.result.checks_run.join(', ')}`
                    : ' · AST parser unavailable for this file type'}
                  {` · ${scopedFindings.length} finding(s) for this file`}
                </p>
                <div className="analyzer-tabs" role="tablist" aria-label="Scan result views">
                  {[
                    ['findings', 'Findings'],
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
                {view === 'findings' && (
                  <div className="analyzer-findings-layout">
                    <div>
                      <div className="analyzer-finding-controls">
                        <label>
                          Findings
                          <select
                            value={findingScope}
                            onChange={(event) => setFindingScope(event.target.value)}
                          >
                            <option value="file">Selected file</option>
                            <option value="project">All project files</option>
                          </select>
                        </label>
                        <label>
                          Reachability
                          <select value={reachabilityFilter} onChange={(event) => setReachabilityFilter(event.target.value)}>
                            <option value="all">All</option>
                            <option value="REACHABLE_CODE">Reachable</option>
                            <option value="UNREACHABLE_NOISE">Unreachable</option>
                            <option value="unverified">Unverified</option>
                          </select>
                        </label>
                        <label>
                          Severity order
                          <select value={severitySort} onChange={(event) => setSeveritySort(event.target.value)}>
                            <option value="highest">Highest first</option>
                            <option value="lowest">Lowest first</option>
                          </select>
                        </label>
                      </div>
                      <div className="analyzer-finding-list">
                      {visibleFindings.length > 0 ? visibleFindings.map((finding, index) => {
                        const findingPath = finding.file || finding.file_path;
                        const findingFile = files.find((file) => file.filePath === findingPath);
                        const isSelected = findingPath === selectedFile.filePath
                          && selectedLine === finding.line;
                        return (
                        <button
                          type="button"
                          className={`analyzer-finding ${isSelected ? 'is-selected' : ''}`}
                          key={`${finding.source}-${findingPath}-${finding.rule_id}-${finding.line}-${index}`}
                          onClick={() => {
                            if (findingFile) {
                              setSelectedFileId(findingFile.id);
                              setFindingScope('file');
                            }
                            setSelectedLine(finding.line || null);
                            setView('findings');
                          }}
                        >
                          <span className={severityClass(finding.severity || 'INFO')}>{finding.severity || 'INFO'}</span>
                          <strong>{finding.rule_id}</strong>
                          <span>{finding.message}</span>
                          <small>{finding.source} · {findingPath}:{finding.line || '?'} · {finding.reachability || 'UNKNOWN'}</small>
                        </button>
                        );
                      }) : <p className="analyzer-empty">No findings match these filters.</p>}
                      </div>
                    </div>
                    <div className="analyzer-source-view" aria-label="Source with selected finding line highlighted">
                      {sourceLines.map((line, index) => {
                        const lineNumber = index + 1;
                        return (
                          <div
                            className={`analyzer-source-line ${selectedLine === lineNumber ? 'is-highlighted' : ''}`}
                            key={lineNumber}
                          >
                            <button type="button" onClick={() => setSelectedLine(lineNumber)}>{lineNumber}</button>
                            <code>{line || ' '}</code>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
                {view === 'cfg' && selectedResult?.result && (
                  <ControlFlowView cfg={selectedResult.result.cfg} onSelectLine={setSelectedLine} />
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
