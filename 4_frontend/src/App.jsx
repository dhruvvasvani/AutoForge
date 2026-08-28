import { useState } from "react";
import "./App.css";

function App() {
  const [status, setStatus] = useState("idle");
  const [result, setResult] = useState("");
  const [error, setError] = useState("");

  const handleGenerateFix = async () => {
    setStatus("analyzing");
    setResult("");
    setError("");

    try {
      const response = await fetch("http://localhost:5050/api/fix", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          code: `String query = "SELECT * FROM users WHERE id = '" + userId + "'";`,
          language: "Java",
          vulnerability: "SQL Injection",
        }),
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || "Failed to generate AI fix");
      }

      setResult(data.result);
      setStatus("generated");
    } catch (err) {
      console.error("Frontend error:", err);
      setError(err.message);
      setStatus("error");
    }
  };

  const steps = [
    {
      number: "01",
      title: "Issue detected",
      description: "SQL Injection vulnerability identified",
      done: true,
    },
    {
      number: "02",
      title: "Gemini analysis",
      description: "AI is reviewing the vulnerable code",
      done: status === "analyzing" || status === "generated",
      active: status === "analyzing",
    },
    {
      number: "03",
      title: "Fix generated",
      description: "Secure remediation is ready",
      done: status === "generated",
    },
    {
      number: "04",
      title: "Create branch",
      description: "Waiting for GitHub integration",
      done: false,
    },
    {
      number: "05",
      title: "Create Pull Request",
      description: "Waiting for GitHub integration",
      done: false,
    },
  ];

  return (
    <div className="app">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">A</div>
          <div>
            <h1>AutoForge</h1>
            <span>SECURITY PLATFORM</span>
          </div>
        </div>

        <nav className="navigation">
          <p className="nav-label">PLATFORM</p>

          <a className="nav-item active" href="#">
            <span>▦</span>
            Dashboard
          </a>

          <a className="nav-item" href="#">
            <span>◈</span>
            Vulnerabilities
            <b>12</b>
          </a>

          <a className="nav-item" href="#">
            <span>✦</span>
            AI Fixes
            <b>8</b>
          </a>

          <a className="nav-item" href="#">
            <span>⑂</span>
            Pull Requests
            <b>3</b>
          </a>

          <p className="nav-label second">SYSTEM</p>

          <a className="nav-item" href="#">
            <span>⚙</span>
            Settings
          </a>

          <a className="nav-item" href="#">
            <span>?</span>
            Documentation
          </a>
        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="green-dot"></span>
            <div>
              <strong>All systems operational</strong>
              <small>Backend services online</small>
            </div>
          </div>

          <div className="profile">
            <div className="avatar">K</div>
            <div>
              <strong>Kartik</strong>
              <small>Developer</small>
            </div>
            <span className="profile-more">•••</span>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="main">
        {/* Topbar */}
        <header className="topbar">
          <div className="breadcrumb">
            <span>AutoForge</span>
            <b>/</b>
            <strong>Security Dashboard</strong>
          </div>

          <div className="topbar-right">
            <div className="search">
              <span>⌕</span>
              <input placeholder="Search vulnerabilities..." />
              <kbd>⌘ K</kbd>
            </div>

            <div className="backend-status">
              <span className="green-dot"></span>
              Backend Online
            </div>

            <button className="notification">♢</button>
          </div>
        </header>

        <div className="content">
          {/* Page heading */}
          <section className="heading">
            <div>
              <p className="eyebrow">OVERVIEW</p>
              <h2>Security Dashboard</h2>
              <p>
                Detect vulnerabilities, generate secure fixes, and automate
                remediation.
              </p>
            </div>

            <div className="repo-box">
              <span>REPOSITORY</span>
              <strong>⌘ dhruvvasvani / AutoForge</strong>
              <small>main</small>
            </div>
          </section>

          {/* Stats */}
          <section className="stats">
            <div className="stat-card">
              <div className="stat-top">
                <span>VULNERABILITIES</span>
                <div className="stat-icon red">!</div>
              </div>
              <strong>12</strong>
              <p><span className="red-text">3 high</span> severity</p>
            </div>

            <div className="stat-card">
              <div className="stat-top">
                <span>AI FIXES</span>
                <div className="stat-icon purple">✦</div>
              </div>
              <strong>8</strong>
              <p><span className="purple-text">67%</span> remediation rate</p>
            </div>

            <div className="stat-card">
              <div className="stat-top">
                <span>PULL REQUESTS</span>
                <div className="stat-icon blue">⑂</div>
              </div>
              <strong>3</strong>
              <p><span className="blue-text">2 merged</span> this week</p>
            </div>

            <div className="stat-card">
              <div className="stat-top">
                <span>SYSTEM STATUS</span>
                <div className="stat-icon green">✓</div>
              </div>
              <strong className="operational">100%</strong>
              <p><span className="green-text">All systems</span> operational</p>
            </div>
          </section>

          {/* Main grid */}
          <div className="dashboard-grid">
            {/* Vulnerability */}
            <section className="panel vulnerability-panel">
              <div className="panel-header">
                <div>
                  <div className="tag-row">
                    <span className="severity high">HIGH</span>
                    <span className="issue-id">ISSUE #001</span>
                  </div>
                  <h3>SQL Injection</h3>
                  <p>Unsanitized user input is directly concatenated into a SQL query.</p>
                </div>

                <span className="open-status">OPEN</span>
              </div>

              <div className="issue-meta">
                <div>
                  <span>FILE</span>
                  <strong>src/User.java</strong>
                </div>

                <div>
                  <span>LINE</span>
                  <strong>42</strong>
                </div>

                <div>
                  <span>RULE</span>
                  <strong>SQL_INJECTION</strong>
                </div>
              </div>

              <div className="code-section">
                <div className="code-header">
                  <span>VULNERABLE CODE</span>
                  <span>JAVA</span>
                </div>

                <div className="code">
                  <div className="line-number">40</div>
                  <div className="line-number">41</div>
                  <div className="line-number active-line">42</div>
                  <div className="line-number">43</div>

                  <div className="code-lines">
                    <div>String userId = request.getParameter("id");</div>
                    <div> </div>
                    <div className="danger-line">
                      String query = "SELECT * FROM users WHERE id = '" +
                      userId + "'";
                    </div>
                    <div>statement.executeQuery(query);</div>
                  </div>
                </div>
              </div>

              <div className="vulnerability-warning">
                <span>⚠</span>
                <div>
                  <strong>Security risk detected</strong>
                  <p>
                    User-controlled input can manipulate the SQL statement and
                    access unauthorized database records.
                  </p>
                </div>
              </div>

              <button
                className="generate-button"
                onClick={handleGenerateFix}
                disabled={status === "analyzing"}
              >
                <span>✦</span>
                {status === "idle" && "Generate AI Fix"}
                {status === "analyzing" && "Analyzing with Gemini..."}
                {status === "generated" && "AI Fix Generated ✓"}
                {status === "error" && "Try Again"}
                {status === "idle" && <b>→</b>}
              </button>

              {error && (
                <div className="error-box">
                  <strong>Something went wrong</strong>
                  <span>{error}</span>
                </div>
              )}
            </section>

            {/* AI panel */}
            <section className="panel ai-panel">
              <div className="ai-heading">
                <div className="ai-icon">✦</div>
                <div>
                  <p className="eyebrow">GEMINI AI</p>
                  <h3>AI Remediation</h3>
                </div>

                {status === "generated" && (
                  <span className="ready-badge">READY</span>
                )}
              </div>

              <p className="ai-description">
                Generate a secure remediation automatically without changing
                unrelated functionality.
              </p>

              {status === "idle" && (
                <div className="ai-empty">
                  <div className="empty-icon">✦</div>
                  <strong>Ready to analyze</strong>
                  <p>
                    Click "Generate AI Fix" to have Gemini analyze this
                    vulnerability.
                  </p>
                </div>
              )}

              {status === "analyzing" && (
                <div className="ai-processing">
                  <div className="spinner"></div>
                  <strong>Gemini is analyzing...</strong>
                  <p>Reviewing vulnerable code and security context</p>
                </div>
              )}

              {status === "generated" && (
                <>
                  <div className="fix-label">
                    <span>AI-GENERATED FIX</span>
                    <span className="secure-label">✓ SECURE</span>
                  </div>

                  <div className="result-code">
                    <pre>{result}</pre>
                  </div>

                  <div className="secure-message">
                    <span>✓</span>
                    <div>
                      <strong>Parameterized query detected</strong>
                      <p>
                        User input is safely separated from the SQL statement.
                      </p>
                    </div>
                  </div>

                  <button className="pr-button">
                    <span>⑂</span>
                    Create Pull Request
                    <b>→</b>
                  </button>
                </>
              )}
            </section>
          </div>

          {/* Automation */}
          <section className="panel automation-panel">
            <div className="automation-heading">
              <div>
                <p className="eyebrow">AUTOMATION PIPELINE</p>
                <h3>Remediation Workflow</h3>
              </div>

              <span
                className={
                  status === "generated"
                    ? "workflow-status complete"
                    : "workflow-status"
                }
              >
                {status === "generated" ? "FIX READY" : "IN PROGRESS"}
              </span>
            </div>

            <div className="pipeline">
              {steps.map((step, index) => (
                <div className="pipeline-step" key={step.number}>
                  <div
                    className={`step-circle ${
                      step.done ? "done" : ""
                    } ${step.active ? "active" : ""}`}
                  >
                    {step.done ? "✓" : step.number}
                  </div>

                  <div className="step-info">
                    <strong>{step.title}</strong>
                    <span>{step.description}</span>
                  </div>

                  {index !== steps.length - 1 && (
                    <div className={`step-line ${step.done ? "done" : ""}`}></div>
                  )}
                </div>
              ))}
            </div>
          </section>

          {/* Bottom */}
          <div className="bottom-grid">
            <section className="panel activity-panel">
              <div className="panel-title">
                <div>
                  <p className="eyebrow">RECENT ACTIVITY</p>
                  <h3>Security Activity</h3>
                </div>
                <button>View all →</button>
              </div>

              <div className="activity">
                <div className="activity-icon red">!</div>
                <div>
                  <strong>SQL Injection detected</strong>
                  <p>src/User.java • 2 minutes ago</p>
                </div>
                <span className="activity-open">OPEN</span>
              </div>

              <div className="activity">
                <div className="activity-icon purple">✦</div>
                <div>
                  <strong>AI fix generated</strong>
                  <p>SQL_INJECTION • Just now</p>
                </div>
                <span className="activity-ready">READY</span>
              </div>

              <div className="activity">
                <div className="activity-icon green">✓</div>
                <div>
                  <strong>Pull Request merged</strong>
                  <p>#27 • 1 hour ago</p>
                </div>
                <span className="activity-merged">MERGED</span>
              </div>
            </section>

            <section className="panel insights-panel">
              <div className="panel-title">
                <div>
                  <p className="eyebrow">SECURITY INSIGHTS</p>
                  <h3>Risk Overview</h3>
                </div>
              </div>

              <div className="risk-chart">
                <div className="risk-number">
                  <strong>Low</strong>
                  <span>Overall Risk</span>
                </div>

                <div className="risk-bars">
                  <div>
                    <span>Critical</span>
                    <i className="bar critical" style={{ width: "0%" }}></i>
                    <b>0</b>
                  </div>
                  <div>
                    <span>High</span>
                    <i className="bar high-bar" style={{ width: "45%" }}></i>
                    <b>3</b>
                  </div>
                  <div>
                    <span>Medium</span>
                    <i className="bar medium" style={{ width: "70%" }}></i>
                    <b>5</b>
                  </div>
                  <div>
                    <span>Low</span>
                    <i className="bar low" style={{ width: "55%" }}></i>
                    <b>4</b>
                  </div>
                </div>
              </div>
            </section>
          </div>

          <footer>
            <span>AutoForge v1.0.0</span>
            <span>•</span>
            <span>AI-powered security remediation</span>
            <span>•</span>
            <span>Gemini connected</span>
          </footer>
        </div>
      </main>
    </div>
  );
}

export default App;
