import { useState } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import './AuthPage.css';

const LoginPage = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { login, loading, error, clearError } = useAuth();

  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });

  const [validationError, setValidationError] = useState(location.state?.message || '');

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
    setValidationError('');
    clearError();
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setValidationError('');

    if (!formData.email || !formData.password) {
      setValidationError('Please fill in all fields');
      return;
    }

    if (!formData.email.includes('@')) {
      setValidationError('Please enter a valid email address');
      return;
    }

    const result = await login(formData.email, formData.password);

    if (result.success) {
      navigate('/dashboard');
    } else {
      setValidationError(result.error || 'Login failed');
    }
  };

  return (
    <main className="auth-page">
      <section className="auth-card">
        <header className="auth-card__header">
          <h1>AutoForge</h1>
          <p>Security Scan &amp; Fix Platform</p>
        </header>

        <form onSubmit={handleSubmit} className="auth-form">
          {(error || validationError) && (
            <div className="auth-error" role="alert">
              <p>{error || validationError}</p>
            </div>
          )}

          <div className="auth-field">
            <label htmlFor="email">
              Email Address
            </label>
            <input
              id="email"
              name="email"
              type="email"
              value={formData.email}
              onChange={handleChange}
              placeholder="you@example.com"
              className="auth-input"
              disabled={loading}
            />
          </div>

          <div className="auth-field">
            <label htmlFor="password">
              Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              value={formData.password}
              onChange={handleChange}
              placeholder="••••••••"
              className="auth-input"
              disabled={loading}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="auth-submit"
          >
            {loading ? 'Logging in...' : 'Log In'}
          </button>

          <p className="auth-helper">
            Don't have an account?{' '}
            <Link to="/register" className="auth-link">
              Sign Up
            </Link>
          </p>

          <p className="auth-helper">
            <a href="#" className="auth-link">
              Forgot your password?
            </a>
          </p>
        </form>

        <footer className="auth-card__footer">
          <p>
            © 2026 AutoForge. All rights reserved.
          </p>
        </footer>
      </section>
    </main>
  );
};

export default LoginPage;
