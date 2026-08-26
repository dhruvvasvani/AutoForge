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

  return (
    <div className="app">

      {/* Header */}
      <header className="header">
        <div className="logo-section">
          <div className="logo-mark">A</div>

          <div>
            <h1>AutoForge</h1>
            <p>AI Security Remediation</p>
          </div>
        </div>

        <div className="connection">
          <span className="status-dot"></span>
          Pipeline Connected
        </div>
      </header>

      {/* Main */}
      <main className="dashboard">

        <div className="page-heading">
          <div>
            <p className="eyebrow">SECURITY DASHBOARD</p>

            <h2>Security Issues</h2>

            <p className="subtitle">
              Review vulnerabilities and generate AI-powered fixes.
            </p>
          </div>

          <div className="repository">
            <span>Repository</span>
            <strong>dhruvvasvani/AutoForge</strong>
          </div>
        </div>

        {/* Issue Card */}
        <section className="issue-card">

          <div className="issue-header">
            <div>
              <span className="severity high">HIGH</span>
              <h3>SQL Injection</h3>
            </div>

            <span className="issue-number">#001</span>
          </div>

          <div className="issue-details">

            <div>
              <span className="detail-label">FILE</span>
              <strong>src/User.java</strong>
            </div>

            <div>
              <span className="detail-label">LINE</span>
              <strong>42</strong>
            </div>

            <div>
              <span className="detail-label">RULE</span>
              <strong>SQL_INJECTION</strong>
            </div>

          </div>

          <div className="code-block">

            <div className="code-header">
              <span>Vulnerable Code</span>
              <span>Java</span>
            </div>

            <pre>
{`String query = "SELECT * FROM users WHERE id = '" + userId + "'";`}
            </pre>

          </div>

          <div className="issue-actions">

            <button
              className="generate-button"
              onClick={handleGenerateFix}
              disabled={status === "analyzing"}
            >
              {status === "idle" && "Generate AI Fix"}

              {status === "analyzing" &&
                "Analyzing with Gemini..."}

              {status === "generated" &&
                "✓ AI Fix Generated"}

              {status === "error" &&
                "Try Again"}
            </button>

          </div>

        </section>

        {/* Error */}
        {status === "error" && (
          <section className="status-card">
            <h3>Something went wrong</h3>

            <p>
              {error}
            </p>
          </section>
        )}

        {/* Status */}
        <section className="status-card">

          <div className="status-title">

            <div>
              <p className="eyebrow">AUTOMATION</p>
              <h3>AI Fix Status</h3>
            </div>

            {status === "analyzing" && (
              <span className="processing">
                Processing...
              </span>
            )}

            {status === "generated" && (
              <span className="success">
                Complete
              </span>
            )}

          </div>

          <div className="timeline">

            {/* Step 1 */}
            <div className="timeline-item completed">

              <div className="timeline-icon">
                ✓
              </div>

              <div>
                <strong>Issue received</strong>

                <p>
                  Security vulnerability detected
                </p>
              </div>

            </div>

            {/* Step 2 */}
            <div
              className={`timeline-item ${
                status === "analyzing" ||
                status === "generated"
                  ? "completed"
                  : ""
              }`}
            >

              <div className="timeline-icon">
                {status === "analyzing" ||
                status === "generated"
                  ? "✓"
                  : "2"}
              </div>

              <div>
                <strong>Gemini analyzing</strong>

                <p>
                  AI is reviewing the vulnerable code
                </p>
              </div>

            </div>

            {/* Step 3 */}
            <div
              className={`timeline-item ${
                status === "generated"
                  ? "completed"
                  : ""
              }`}
            >

              <div className="timeline-icon">
                {status === "generated"
                  ? "✓"
                  : "3"}
              </div>

              <div>
                <strong>Fix generated</strong>

                <p>
                  AI-generated remediation is ready
                </p>
              </div>

            </div>

            {/* Step 4 */}
            <div className="timeline-item">

              <div className="timeline-icon">
                4
              </div>

              <div>
                <strong>Creating branch</strong>

                <p>
                  Waiting for GitHub integration
                </p>
              </div>

            </div>

            {/* Step 5 */}
            <div className="timeline-item">

              <div className="timeline-icon">
                5
              </div>

              <div>
                <strong>Creating Pull Request</strong>

                <p>
                  Waiting for GitHub integration
                </p>
              </div>

            </div>

          </div>

        </section>

        {/* AI Result */}
        {status === "generated" && (

          <section className="fix-preview">

            <div>

              <p className="eyebrow">
                AI RESULT
              </p>

              <h3>
                Fix Ready
              </h3>

              <p>
                Gemini generated a remediation using
                a parameterized query.
              </p>

            </div>

            <div className="ai-result">

              <pre>
                {result}
              </pre>

            </div>

            <button className="pr-button">
              Create Pull Request →
            </button>

          </section>

        )}

      </main>

    </div>
  );
}

export default App;
