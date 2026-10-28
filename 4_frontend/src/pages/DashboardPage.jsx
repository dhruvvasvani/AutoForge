import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { repositoryAPI, scanAPI } from '../api/client';
import LocalAnalyzer from '../components/LocalAnalyzer';
import './DashboardPage.css';

const ACTIVE_SCAN_STATES = new Set(['QUEUED', 'RUNNING']);

function RepositoryScanProgress({ repository }) {
  const [scans, setScans] = useState([]);
  const [error, setError] = useState('');
  const [triggering, setTriggering] = useState(false);
  const [scanMessage, setScanMessage] = useState('');
  const [findings, setFindings] = useState([]);
  const [findingsError, setFindingsError] = useState('');

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
    setFindingsError('');
    try {
      const response = await scanAPI.triggerScan(repository.id);
      setScanMessage(`Queued scan for commit ${response.data.commitSha?.slice(0, 10) || 'latest'}.`);
      try {
        const history = await repositoryAPI.getScanHistory(repository.id);
        setScans(history.data || []);
      } catch {
        setError('Scan was queued, but its progress could not be refreshed yet.');
      }
    } catch (scanError) {
      setError(
        scanError.response?.data?.message
          || scanError.response?.data?.detail
          || 'Could not fetch and queue the latest GitHub commit. Public repositories only; check backend and Redis status.',
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
          <strong>{latest.progressStage || latest.status}</strong>
          <p>{latest.progressMessage || (ACTIVE_SCAN_STATES.has(latest.status)
            ? 'Waiting for worker progress…'
            : `Commit ${latest.commitSha?.slice(0, 10) || 'unknown'}`)}</p>
          {ACTIVE_SCAN_STATES.has(latest.status) && (
            <progress aria-label={`Scan ${latest.id} progress`} />
          )}
        </>
      ) : null}
      {latest?.status === 'COMPLETED' && (
        <section className="dashboard-scan-findings" aria-label="AST scan findings">
          <strong>Findings for commit {latest.commitSha?.slice(0, 10) || 'unknown'}</strong>
          {findingsError ? (
            <p role="status">{findingsError}</p>
          ) : findings.length ? (
            <ul>
              {findings.map((finding) => (
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
                  {finding.description && <p>{finding.description}</p>}
                </li>
              ))}
            </ul>
          ) : (
            <p>No findings were persisted for this scan.</p>
          )}
        </section>
      )}
    </div>
  );
}

const DashboardPage = () => {
  const { user, logout } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [repositories, setRepositories] = useState([]);
  const [repositoryInput, setRepositoryInput] = useState('');
  const [connectingRepository, setConnectingRepository] = useState(false);
  const [repositoryActionError, setRepositoryActionError] = useState('');

  const fetchDashboardData = useCallback(() => repositoryAPI.getAll(), []);
  const reportRepositoryError = useCallback((err) => {
    setError(err.response?.data?.message || 'Could not load repositories. Check that the backend is running.');
    console.error('Dashboard error:', err);
  }, []);

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
    const githubRepoFullName = repositoryInput.trim();
    if (!/^[A-Za-z0-9_-][A-Za-z0-9_.-]*\/[A-Za-z0-9_-][A-Za-z0-9_.-]*$/.test(githubRepoFullName)) {
      setRepositoryActionError('Enter a GitHub repository as owner/repository.');
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
              <label htmlFor="github-repository">Public GitHub repository</label>
              <div>
                <input
                  id="github-repository"
                  name="github-repository"
                  value={repositoryInput}
                  onChange={(event) => setRepositoryInput(event.target.value)}
                  placeholder="owner/repository"
                  maxLength={201}
                  disabled={connectingRepository}
                />
                <button type="submit" disabled={connectingRepository || !repositoryInput.trim()}>
                  {connectingRepository ? 'Connecting…' : 'Connect'}
                </button>
              </div>
              {repositoryActionError && <p role="alert">{repositoryActionError}</p>}
              <small>Public repositories only; private access is not configured.</small>
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
