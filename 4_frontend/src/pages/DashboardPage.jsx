import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { repositoryAPI } from '../api/client';
import LocalAnalyzer from '../components/LocalAnalyzer';

const DashboardPage = () => {
  const { user, logout } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [repositories, setRepositories] = useState([]);

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

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">AutoForge</h1>
            <p className="text-gray-600 text-sm">Security Scan Dashboard</p>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-sm font-medium text-gray-900">{user?.fullName || user?.username}</p>
              <p className="text-xs text-gray-500">{user?.email}</p>
            </div>
            <button
              onClick={handleLogout}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-md text-sm font-medium transition"
            >
              Logout
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
            <p className="text-red-600 text-sm">{error}</p>
            <button
              onClick={retryLoading}
              className="mt-2 text-red-600 hover:text-red-700 text-sm font-medium"
            >
              Try again
            </button>
          </div>
        )}

        <LocalAnalyzer />

        <section className="bg-white rounded-lg shadow mt-8">
          <div className="border-b border-gray-200 px-6 py-4">
            <h2 className="text-lg font-bold text-gray-900">Your Repositories</h2>
          </div>
          <div className="divide-y divide-gray-200">
            {repositories.length > 0 ? (
              repositories.map((repo) => (
                <div key={repo.id} className="px-6 py-4">
                  <p className="font-medium text-gray-900">{repo.name}</p>
                  <p className="text-sm text-gray-500">{repo.url}</p>
                </div>
              ))
            ) : (
              <div className="px-6 py-8 text-center text-gray-500">
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
