import { useState } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import './AuthPage.css';

const RegisterPage = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { register, loading, error, clearError } = useAuth();

  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
  });

  const [validationError, setValidationError] = useState(location.state?.message || '');
  const [agreeToTerms, setAgreeToTerms] = useState(false);

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

    if (!formData.username || !formData.email || !formData.password || !formData.confirmPassword) {
      setValidationError('Please fill in all fields');
      return;
    }

    if (formData.username.length < 3) {
      setValidationError('Username must be at least 3 characters');
      return;
    }

    if (!formData.email.includes('@')) {
      setValidationError('Please enter a valid email address');
      return;
    }

    if (formData.password.length < 8) {
      setValidationError('Password must be at least 8 characters');
      return;
    }

    if (formData.password !== formData.confirmPassword) {
      setValidationError('Passwords do not match');
      return;
    }

    if (!agreeToTerms) {
      setValidationError('Please agree to the Terms of Service');
      return;
    }

    const result = await register(
      formData.username,
      formData.email,
      formData.password,
      formData.confirmPassword
    );

    if (result.success) {
      navigate('/dashboard');
    } else {
      setValidationError(result.error || 'Registration failed');
    }
  };

  return (
    <main className="auth-page">
      <section className="auth-card">
        <header className="auth-card__header">
          <h1>AutoForge</h1>
          <p>Create an account</p>
        </header>

        <form onSubmit={handleSubmit} className="auth-form">
          {(error || validationError) && (
            <div className="auth-error" role="alert">
              <p>{error || validationError}</p>
            </div>
          )}

          <div className="auth-field">
            <label htmlFor="username">
              Username
            </label>
            <input
              id="username"
              name="username"
              type="text"
              value={formData.username}
              onChange={handleChange}
              placeholder="yourname"
              className="auth-input"
              disabled={loading}
            />
          </div>

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
            <p className="auth-field__hint">At least 8 characters</p>
          </div>

          <div className="auth-field">
            <label htmlFor="confirmPassword">
              Confirm Password
            </label>
            <input
              id="confirmPassword"
              name="confirmPassword"
              type="password"
              value={formData.confirmPassword}
              onChange={handleChange}
              placeholder="••••••••"
              className="auth-input"
              disabled={loading}
            />
          </div>

          <div className="auth-terms">
            <label>
              <input
                type="checkbox"
                checked={agreeToTerms}
                onChange={(e) => setAgreeToTerms(e.target.checked)}
                className="auth-checkbox"
              />
              <span>
                I agree to the{' '}
                <a href="#" className="auth-link">
                  Terms of Service
                </a>
              </span>
            </label>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="auth-submit"
          >
            {loading ? 'Creating Account...' : 'Sign Up'}
          </button>

          <p className="auth-helper">
            Already have an account?{' '}
            <Link to="/login" className="auth-link">
              Log In
            </Link>
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

export default RegisterPage;
