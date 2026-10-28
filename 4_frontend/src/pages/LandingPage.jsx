import { Link } from 'react-router-dom';
import './LandingPage.css';

const pipeline = [
  ['01', 'Connect', 'Link a GitHub repository and choose the branch to watch.'],
  ['02', 'Scan', 'Semgrep and Checkov look for security problems.'],
  ['03', 'Filter', 'Reachability analysis separates live risks from dead-code noise.'],
  ['04', 'Prioritize', 'Clear severity and risk scores put real issues first.'],
  ['05', 'Fix', 'AI drafts a focused patch for the findings that matter.'],
  ['06', 'Review', 'You review the diff before a pull request is opened.'],
];

const plans = [
  {
    name: 'Free',
    description: 'Start exploring the full security workflow.',
    features: ['Repository scanning', 'Reachability analysis', 'Prioritized findings'],
    action: 'Create a free account',
    to: '/register',
    featured: false,
  },
  {
    name: 'Team',
    description: 'More room to secure the projects you ship.',
    features: ['Everything in Free', 'Higher repository limits', 'Team-ready scan workflow'],
    action: 'Get started',
    to: '/register',
    featured: true,
  },
];

function Brand({ footer = false }) {
  return (
    <Link className={`landing-brand${footer ? ' landing-brand--footer' : ''}`} to="/">
      <span className="landing-brand__mark" aria-hidden="true">
        A
      </span>
      <span>AutoForge</span>
    </Link>
  );
}

function LandingPage() {
  return (
    <main className="landing-page" id="top">
      <header className="landing-header">
        <Brand />
        <nav className="landing-nav" aria-label="Main navigation">
          <a href="#how-it-works">How it works</a>
          <a href="#plans">Plans</a>
          <a href="#faq">FAQ</a>
        </nav>
        <div className="landing-header__actions">
          <Link className="landing-link-button" to="/login">
            Sign in
          </Link>
          <Link className="landing-button landing-button--small" to="/register">
            Get started <span aria-hidden="true">↗</span>
          </Link>
        </div>
      </header>

      <section className="landing-hero" aria-labelledby="landing-title">
        <div className="landing-hero__copy">
          <div className="landing-kicker">
            <span className="landing-status-dot" />
            SECURITY THAT KEEPS UP WITH YOU
          </div>
          <h1 id="landing-title">
            Ship code.
            <br />
            <span>Not security debt.</span>
          </h1>
          <p>
            AutoForge scans your code, cuts through dead-code alerts, and helps
            you fix the vulnerabilities that actually matter.
          </p>
          <div className="landing-hero__actions">
            <Link className="landing-button" to="/register">
              Start securing for free <span aria-hidden="true">↗</span>
            </Link>
            <Link className="landing-secondary-link" to="/analyze">
              Try local AST scan <span aria-hidden="true">↗</span>
            </Link>
          </div>
          <div className="landing-hero__trust">
            <span aria-hidden="true">✳</span> Human-reviewed fixes. Your code stays yours.
          </div>
        </div>

        <div className="landing-preview" aria-label="Example security scan dashboard">
          <div className="landing-preview__topbar">
            <div className="landing-window-dots" aria-hidden="true">
              <i />
              <i />
              <i />
            </div>
            <span>ILLUSTRATIVE PREVIEW · NOT A LIVE SCAN</span>
            <span className="landing-preview__live">
              <span className="landing-status-dot" /> SCAN COMPLETE
            </span>
          </div>
          <div className="landing-preview__body">
            <div className="landing-code">
              <div className="landing-code__header">
                <span>src / db / users.py</span>
                <span>main</span>
              </div>
              <pre aria-label="Example code finding">
                <code>
                  <span className="code-muted">14 </span>
                  <span className="code-purple">def </span>
                  <span className="code-blue">get_user</span>
                  <span>(name):</span>
                  {'\n'}
                  <span className="code-muted">15 </span>
                  <span>  query = </span>
                  <span className="code-green">"SELECT * FROM users"</span>
                  {'\n'}
                  <span className="code-muted">16 </span>
                  <span>  cursor.execute(query + name)</span>
                  {'\n'}
                  <span className="code-muted">17 </span>
                  <span>  return cursor.fetchone()</span>
                </code>
              </pre>
              <div className="landing-code__finding">
                <span className="landing-severity">HIGH</span>
                <span>Possible SQL injection</span>
                <span className="landing-code__line">Line 16</span>
              </div>
            </div>

            <div className="landing-scan-summary">
              <p className="landing-scan-summary__label">YOUR SECURITY SNAPSHOT</p>
              <h2>Less noise. More signal.</h2>
              <div className="landing-metric">
                <span className="landing-metric__icon landing-metric__icon--violet">⌘</span>
                <span><strong>24</strong><small>Issues found</small></span>
                <b>+3</b>
              </div>
              <div className="landing-metric">
                <span className="landing-metric__icon landing-metric__icon--green">✓</span>
                <span><strong>18</strong><small>Actionable</small></span>
                <b className="landing-metric__good">−42%</b>
              </div>
              <div className="landing-metric">
                <span className="landing-metric__icon landing-metric__icon--amber">◎</span>
                <span><strong>6</strong><small>Noise filtered</small></span>
                <b>Reachability</b>
              </div>
              <div className="landing-scan-summary__footer">
                <span className="landing-status-dot" />
                Sample scan snapshot · demo data
              </div>
            </div>
          </div>
          <div className="landing-preview__bottom">
            <span><span className="landing-status-dot" /> Workflow preview</span>
            <span>AST analysis <b>✓</b></span>
            <span>Risk scoring <b>✓</b></span>
            <span>AI review <b>✓</b></span>
          </div>
        </div>

        <a className="landing-scroll-cue" href="#how-it-works">
          <span /> BUILT FOR THE WAY YOU SHIP
        </a>
      </section>

      <section className="landing-process landing-section" id="how-it-works">
        <div className="landing-section-heading">
          <div>
            <p className="landing-eyebrow">FROM PUSH TO PEACE OF MIND</p>
            <h2>Security, in your flow.</h2>
          </div>
          <p>
            One connected workflow. Find what matters, understand the risk, and
            decide what ships.
          </p>
        </div>
        <div className="landing-pipeline">
          {pipeline.map(([number, title, description]) => (
            <article className="landing-pipeline__step" key={number}>
              <span className="landing-pipeline__number">{number}</span>
              <h3>{title}</h3>
              <p>{description}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="landing-proof landing-section" aria-labelledby="proof-title">
        <div className="landing-proof__card">
          <div>
            <p className="landing-eyebrow">BUILT FOR SIGNAL, NOT NOISE</p>
            <h2 id="proof-title">Make every alert earn your attention.</h2>
            <p>
              AutoForge connects findings to the code paths an attacker can
              actually reach—so your team can focus on real risk.
            </p>
          </div>
          <div className="landing-proof__stats">
            <div><strong>&lt; 3<span>min</span></strong><p>From commit to scan results</p></div>
            <div><strong>6<span>steps</span></strong><p>From push to reviewed fix</p></div>
            <div><strong>1<span>place</span></strong><p>For findings and decisions</p></div>
          </div>
        </div>
      </section>

      <section className="landing-plans landing-section" id="plans">
        <div className="landing-section-heading landing-section-heading--center">
          <div>
            <p className="landing-eyebrow">ROOM TO GROW</p>
            <h2>Start small. Ship safer.</h2>
          </div>
          <p>Get started in minutes. Pick the plan that fits your team.</p>
        </div>
        <div className="landing-plan-grid">
          {plans.map((plan) => (
            <article
              className={`landing-plan${plan.featured ? ' landing-plan--featured' : ''}`}
              key={plan.name}
            >
              <div className="landing-plan__top">
                <span>{plan.name}</span>
                {plan.featured && <span className="landing-plan__badge">FOR TEAMS</span>}
              </div>
              <p>{plan.description}</p>
              <ul>
                {plan.features.map((feature) => (
                  <li key={feature}><span aria-hidden="true">✓</span>{feature}</li>
                ))}
              </ul>
              <Link
                className={`landing-button${plan.featured ? '' : ' landing-button--outline'}`}
                to={plan.to}
              >
                {plan.action} <span aria-hidden="true">↗</span>
              </Link>
            </article>
          ))}
        </div>
      </section>

      <section className="landing-faq landing-section" id="faq">
        <div className="landing-section-heading">
          <div>
            <p className="landing-eyebrow">GOOD QUESTIONS</p>
            <h2>Clear answers.</h2>
          </div>
          <p>Know what happens before you connect a repository.</p>
        </div>
        <div className="landing-faq__list">
          <details>
            <summary>What counts as a machine?</summary>
            <p>
              A machine is a repository, server, or container you want AutoForge
              to watch. Connect a repository to get started.
            </p>
          </details>
          <details>
            <summary>Does AutoForge change my code automatically?</summary>
            <p>
              No. Suggested fixes are presented for your review. You stay in
              control of what gets merged.
            </p>
          </details>
          <details>
            <summary>What does reachability mean?</summary>
            <p>
              Reachability analysis checks whether vulnerable code can be reached
              from an application entry point, helping filter out dead-code noise.
            </p>
          </details>
          <details>
            <summary>Which languages can I scan?</summary>
            <p>
              The local analyzer accepts Python, JavaScript, TypeScript, Java,
              Go, and SQL source files. Supported analysis varies by language.
            </p>
          </details>
        </div>
      </section>

      <section className="landing-cta">
        <p className="landing-eyebrow">YOUR NEXT PUSH CAN BE SAFER</p>
        <h2>Ready to focus on real risk?</h2>
        <p>Connect your project and see the signal behind the noise.</p>
        <div>
          <Link className="landing-button" to="/register">
            Create your free account <span aria-hidden="true">↗</span>
          </Link>
          <Link className="landing-secondary-link" to="/login">Already have an account?</Link>
        </div>
      </section>

      <footer className="landing-footer">
        <div className="landing-footer__brand">
          <Brand footer />
          <p>Thoughtful security for the code you ship.</p>
        </div>
        <p>Government Engineering College, Ajmer</p>
        <div className="landing-footer__links">
          <a href="https://github.com/dhruvvasvani/AutoForge" target="_blank" rel="noreferrer">GitHub ↗</a>
          <a href="#faq">FAQ</a>
          <Link to="/login">Sign in</Link>
        </div>
        <span className="landing-footer__copyright">© 2026 AutoForge</span>
      </footer>
    </main>
  );
}

export default LandingPage;
