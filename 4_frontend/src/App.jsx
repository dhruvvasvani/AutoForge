import { BrowserRouter as Router, Routes, Route, Navigate, Link } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import PrivateRoute from './components/PrivateRoute';

import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import LandingPage from './pages/LandingPage';
import LocalAnalyzer from './components/LocalAnalyzer';

function LocalAnalyzerPage() {
  return (
    <div className="standalone-analyzer-page">
      <header className="standalone-analyzer-page__header">
        <Link to="/" className="standalone-analyzer-page__brand">AutoForge</Link>
        <p>Local AST scans work without the account backend. Scan history and feedback sync are optional.</p>
        <Link to="/">Back to home</Link>
      </header>
      <main className="standalone-analyzer-page__content">
        <LocalAnalyzer />
      </main>
    </div>
  );
}

const LoadingScreen = () => (
  <div className="flex items-center justify-center min-h-screen bg-gray-50">
    <div className="text-center">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
      <p className="text-gray-600">Loading...</p>
    </div>
  </div>
);

function AppRoutes() {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return <LoadingScreen />;
  }

  return (
    <Routes>
      <Route
        path="/login"
        element={isAuthenticated ? <Navigate to="/dashboard" replace /> : <LoginPage />}
      />
      <Route
        path="/register"
        element={isAuthenticated ? <Navigate to="/dashboard" replace /> : <RegisterPage />}
      />

      <Route
        path="/dashboard"
        element={<PrivateRoute element={<DashboardPage />} />}
      />

      <Route
        path="/analyze"
        element={<LocalAnalyzerPage />}
      />

      <Route
        path="/"
        element={<LandingPage />}
      />

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

function App() {
  return (
    <Router>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </Router>
  );
}

export default App;
