import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import { repositoryAPI, scanAPI } from '../api/client';
import LocalAnalyzer from '../components/LocalAnalyzer';
import './DashboardPage.css';

const ACTIVE_SCAN_STATES = new Set(['QUEUED', 'RUNNING']);
const PIPELINE_STEPS = ['Ingest', 'SAST', 'AST Reachability', 'Completed'];
const GITHUB_REPOSITORY_PATTERN = /^[A-Za-z0-9_-][A-Za-z0-9_.-]*\/[A-Za-z0-9_-][A-Za-z0-9_.-]*$/;
const NO_DISMISSED_FINDINGS = new Set();

function normalizeGitHubRepository(value) {
  const input = value.trim();
  let repository = input;

  if (/^(https?:\/\/|www\.|github\.com\/)/i.test(input)) {
    let url;
    try {
      url = new URL(input.startsWith('www.') || input.startsWith('github.com/') ? `https://${input}` : input);
    } catch {
      return null;
    }

    if (
      !['http:', 'https:'].includes(url.protocol)
      || url.hostname.toLowerCase() !== 'github.com'
      || url.port
      || url.username
      || url.password
      || url.search
      || url.hash
    ) {
      return null;
    }

    repository = url.pathname.replace(/^\/|\/$/g, '').replace(/\.git$/i, '');
  }

  return GITHUB_REPOSITORY_PATTERN.test(repository) ? repository : null;
}

const progressStepIndex = (stage) => {
  if (!stage) return -1;
  if (['JOB_RECEIVED', 'REPO_CLONED'].includes(stage)) return 0;
  if (['SEMGREP_DONE', 'CHECKOV_DONE'].includes(stage)) return 1;
  if (stage === 'AST_DONE') return 2;
  if (['RESULTS_POSTED', 'COMPLETED'].includes(stage)) return 3;
  return -1;
};

function RepositoryScanProgress({ repository }) {
  const [scans, setScans] = useState([]);
  const [error, setError] = useState('');
  const [triggering, setTriggering] = useState(false);
  const [scanMessage, setScanMessage] = useState('');
  const [findings, setFindings] = useState([]);
  const [dismissalState, setDismissalState] = useState({ scanId: null, ids: NO_DISMISSED_FINDINGS });
  const [findingsError, setFindingsError] = useState('');
  const [liveProgress, setLiveProgress] = useState(null);

  useEffect(() => {
    let active = true;
    let timer;
    const refresh = () => {
      repositoryAPI.getScanHistory(repository.id)
        .then((response) => {
          if (active) {
            setScans(response.data || []);
            setError('');
          }
        })
        .catch(() => {
          if (active) setError('Scan status is temporarily unavailable.');
        })
        .finally(() => {
          if (active) timer = window.setTimeout(refresh, 5000);
        });
    };
    refresh();
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [repository.id]);

  const latest = scans[0];
  const latestScanId = latest?.id;
  const latestScanStatus = latest?.status;
  const dismissedFindingIds = dismissalState.scanId === latestScanId
    ? dismissalState.ids
    : NO_DISMISSED_FINDINGS;
  const activeFindings = findings.filter(
    (finding) => !dismissedFindingIds.has(String(finding.id)),
  );
  const dismissedFindings = findings.filter(
    (finding) => dismissedFindingIds.has(String(finding.id)),
  );

  useEffect(() => {
    if (!latestScanId) return undefined;
    return scanAPI.subscribeToProgress(
      latestScanId,
      (event) => setLiveProgress({ scanId: latestScanId, ...event }),
    );
  }, [latestScanId]);

  const currentLiveProgress = liveProgress?.scanId === latestScanId ? liveProgress : null;
  const progressStage = currentLiveProgress?.stage || latest?.progressStage || latest?.progress_stage;
  const progressMessage = currentLiveProgress?.message || latest?.progressMessage || latest?.progress_message;
  const commitSha = latest?.commitSha || latest?.commit_sha;
  const activeStep = progressStepIndex(progressStage);
  useEffect(() => {
    if (!latestScanId || latestScanStatus !== 'COMPLETED') return undefined;
    let active = true;
    scanAPI.getFindings(latestScanId)
      .then((response) => {
        if (active) {
          setFindings(response.data || []);
          setFindingsError('');
        }
      })
      .catch(() => {
        if (active) setFindingsError('Scan completed, but findings could not be loaded.');
      });
    return () => {
      active = false;
    };
  }, [latestScanId, latestScanStatus]);

  const triggerScan = async () => {
    setTriggering(true);
    setError('');
    setScanMessage('');
    setFindings([]);
    setDismissalState({ scanId: null, ids: NO_DISMISSED_FINDINGS });
    setFindingsError('');
    try {
      const response = await scanAPI.triggerScan(repository.id);
      const commit = response.data.commitSha || response.data.commit_sha;
      setScanMessage(`Queued scan for commit ${commit?.slice(0, 10) || 'latest'}.`);
      try {
        const history = await repositoryAPI.getScanHistory(repository.id);
        setScans(history.data || []);
      } catch {
        setError('Scan was queued, but its progress could not be refreshed yet.');
      }
    } catch (scanError) {
      setError(
        scanError.response?.data?.message
          || (Array.isArray(scanError.response?.data?.messages) ? scanError.response.data.messages[0] : null)
          || scanError.response?.data?.detail
          || 'Could not fetch and queue the latest GitHub commit. Check the repository URL, GitHub access, backend, and Redis status.',
      );
    } finally {
      setTriggering(false);
    }
  };

  if (!latest && !error && !scanMessage) {
    return (
      <div className="dashboard-scan-progress">
        <button
          type="button"
          className="dashboard-scan-button"
          onClick={triggerScan}
          disabled={triggering || ACTIVE_SCAN_STATES.has(latest?.status)}
        >
          {triggering
            ? 'Fetching latest commit…'
            : ACTIVE_SCAN_STATES.has(latest?.status)
              ? 'Scan in progress…'
              : 'Fetch latest & scan'}
        </button>
        <small>Public GitHub repositories only. Scan results do not change or push code.</small>
      </div>
    );
  }
  return (
    <div className="dashboard-scan-progress" aria-live="polite">
      <button
        type="button"
        className="dashboard-scan-button"
        onClick={triggerScan}
        disabled={triggering || ACTIVE_SCAN_STATES.has(latest?.status)}
      >
        {triggering
          ? 'Fetching latest commit…'
          : ACTIVE_SCAN_STATES.has(latest?.status)
            ? 'Scan in progress…'
            : 'Fetch latest & scan'}
      </button>
      <small>Public GitHub repositories only. Scan results do not change or push code.</small>
      {scanMessage && <p role="status">{scanMessage}</p>}
      {error ? (
        <p role="status">{error}</p>
      ) : latest ? (
        <>
          <span className={`dashboard-scan-progress__status is-${latest.status.toLowerCase()}`}>
            {latest.status}
          </span>
          <strong>{progressStage || latest.status}</strong>
          <p>{progressMessage || (ACTIVE_SCAN_STATES.has(latest.status)
            ? 'Waiting for worker progress…'
            : `Commit ${commitSha?.slice(0, 10) || 'unknown'}`)}</p>
          {ACTIVE_SCAN_STATES.has(latest.status) && (
            <>
              <ol className="dashboard-scan-steps" aria-label="Security scan pipeline">
                {PIPELINE_STEPS.map((step, index) => (
                  <li
                    key={step}
                    className={index < activeStep
                      ? 'is-complete'
                      : index === activeStep
                        ? 'is-active'
                        : ''}
                  >
                    {step}
                  </li>
                ))}
              </ol>
              <progress
                aria-label={`Scan ${latest.id} progress`}
                value={latest.progress ?? 0}
                max="100"
              />
            </>
          )}
        </>
      ) : null}
      {latest?.status === 'COMPLETED' && (
        <section className="dashboard-scan-findings" aria-label="AST scan findings">
          <strong>Findings for commit {commitSha?.slice(0, 10) || 'unknown'}</strong>
          <small>
            {activeFindings.length} active finding(s)
            {dismissedFindings.length
              ? ` · ${dismissedFindings.length} marked false positive for this scan`
              : ''}
          </small>
          <small>Dismissals are temporary, do not change the scan policy result, and reset on a new scan.</small>
          {findingsError ? (
            <p role="status">{findingsError}</p>
          ) : activeFindings.length ? (
            <ul>
              {activeFindings.map((finding) => (
                <li key={finding.id}>
                  <span>{finding.severity || 'Unrated'} · {finding.ruleId || 'Finding'}</span>
                  <code>{finding.filePath || 'unknown file'}:{finding.lineNumber || '?'}</code>
                  <small>
                    {finding.reachable === true
                      ? 'Reachable'
                      : finding.reachable === false
                        ? 'Unreachable'
                        : 'Reachability unverified'}
                    {finding.priority ? ` · ${finding.priority}` : ''}
                    {finding.sourceScanner ? ` · ${finding.sourceScanner}` : ''}
                  </small>
                  {Number.isFinite(finding.cpgGnnFileConfidence) && (
                    <small>
                      CPG-GNN file confidence: {(finding.cpgGnnFileConfidence * 100).toFixed(1)}% (informational)
                    </small>
                  )}
                  {finding.description && <p>{finding.description}</p>}
                  <button
                    type="button"
                    className="dashboard-scan-findings__action"
                    onClick={() => setDismissalState((current) => {
                      const ids = current.scanId === latestScanId
                        ? new Set(current.ids)
                        : new Set();
                      ids.add(String(finding.id));
                      return { scanId: latestScanId, ids };
                    })}
                  >
                    Mark false positive
                  </button>
                </li>
              ))}
            </ul>
          ) : findings.length === 0 ? (
            <p>No findings were persisted for this scan.</p>
          ) : (
            <p>All findings are marked false positive for this scan.</p>
          )}
          {dismissedFindings.length > 0 && (
            <ul aria-label="Findings marked false positive">
              {dismissedFindings.map((finding) => (
                <li key={finding.id}>
                  <span>{finding.severity || 'Unrated'} · {finding.ruleId || 'Finding'} · Marked false positive</span>
                  <code>{finding.filePath || 'unknown file'}:{finding.lineNumber || '?'}</code>
                  <button
                    type="button"
                    className="dashboard-scan-findings__action"
                    onClick={() => setDismissalState((current) => {
                      const ids = current.scanId === latestScanId
                        ? new Set(current.ids)
                        : new Set();
                      ids.delete(String(finding.id));
                      return { scanId: latestScanId, ids };
                    })}
                  >
                    Undo
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  );
}

const DashboardPage = () => {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [repositories, setRepositories] = useState([]);
  const [repositoryInput, setRepositoryInput] = useState('');
  const [connectingRepository, setConnectingRepository] = useState(false);
  const [repositoryActionError, setRepositoryActionError] = useState('');

  const fetchDashboardData = useCallback(() => repositoryAPI.getAll(), []);
  const reportRepositoryError = useCallback((err) => {
    if (err.response?.status === 401 || err.response?.status === 403) {
      logout();
      navigate('/register', {
        replace: true,
        state: {
          message: 'Your previous demo session is not in the new PostgreSQL database. Create your account again to continue.',
        },
      });
      return;
    }
    setError(err.response?.data?.message || 'Could not load repositories. Check that the backend is running.');
    console.error('Dashboard error:', err);
  }, [logout, navigate]);

  useEffect(() => {
    let active = true;
    fetchDashboardData()
      .then((response) => {
        if (active) setRepositories(response.data);
      })
      .catch((err) => {
        if (active) reportRepositoryError(err);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [fetchDashboardData, reportRepositoryError]);

  const handleLogout = () => {
    logout();
  };

  const retryLoading = () => {
    setLoading(true);
    setError(null);
    fetchDashboardData()
      .then((response) => setRepositories(response.data))
      .catch(reportRepositoryError)
      .finally(() => setLoading(false));
  };

  const connectRepository = async (event) => {
    event.preventDefault();
    const githubRepoFullName = normalizeGitHubRepository(repositoryInput);
    if (!githubRepoFullName) {
      setRepositoryActionError('Enter a GitHub repository as owner/repository or paste its github.com URL.');
      return;
    }
    setConnectingRepository(true);
    setRepositoryActionError('');
    try {
      const response = await repositoryAPI.create({ githubRepoFullName });
      setRepositories((current) => [...current, response.data]);
      setRepositoryInput('');
    } catch (connectError) {
      setRepositoryActionError(
        connectError.response?.data?.message
          || connectError.response?.data?.detail
          || 'Could not connect this repository.',
      );
    } finally {
      setConnectingRepository(false);
    }
  };

  if (loading) {
    return (
      <div className="dashboard-loading">
        <div>
          <span className="dashboard-loading__spinner" aria-hidden="true"></span>
          <p>Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-page">
      <header className="dashboard-header">
        <div className="dashboard-header__inner">
          <div>
            <h1>AutoForge</h1>
            <p>Security Scan Dashboard</p>
          </div>
          <div className="dashboard-account">
            <div>
              <p className="dashboard-account__name">{user?.fullName || user?.username}</p>
              <p className="dashboard-account__email">{user?.email}</p>
            </div>
            <button
              onClick={handleLogout}
              className="dashboard-logout"
            >
              Logout
            </button>
          </div>
        </div>
      </header>

      <main className="dashboard-main">
        {error && (
          <div className="dashboard-repository-error" role="alert">
            <p>{error}</p>
            <button
              onClick={retryLoading}
              className="dashboard-retry"
            >
              Try again
            </button>
          </div>
        )}

        <LocalAnalyzer />

        <section className="dashboard-repositories">
          <div className="dashboard-repositories__header">
            <h2>Your Repositories</h2>
            <form className="dashboard-repository-connect" onSubmit={connectRepository}>
              <label htmlFor="github-repository">GitHub repository</label>
              <div>
                <input
                  id="github-repository"
                  name="github-repository"
                  value={repositoryInput}
                  onChange={(event) => setRepositoryInput(event.target.value)}
                  placeholder="owner/repository or GitHub URL"
                  maxLength={201}
                  disabled={connectingRepository}
                />
                <button type="submit" disabled={connectingRepository || !repositoryInput.trim()}>
                  {connectingRepository ? 'Connecting…' : 'Connect'}
                </button>
              </div>
              {repositoryActionError && <p role="alert">{repositoryActionError}</p>}
              <small>Public repositories work without a token. Private repositories need a server-side GITHUB_TOKEN with Contents: read access.</small>
            </form>
          </div>
          <div className="dashboard-repositories__list">
            {repositories.length > 0 ? (
              repositories.map((repo) => (
                <div key={repo.id} className="dashboard-repository">
                  <p className="dashboard-repository__name">{repo.githubRepoFullName}</p>
                  <p className="dashboard-repository__url">{repo.githubRepoFullName}</p>
                  <RepositoryScanProgress repository={repo} />
                </div>
              ))
            ) : (
              <div className="dashboard-repositories__empty">
                <p>No repositories connected yet.</p>
              </div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
};

export default DashboardPage;
