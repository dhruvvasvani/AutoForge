import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { dashboardAPI, scanAPI, repositoryAPI } from '../api/client';

const DashboardPage = () => {
  const { user, logout } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [summary, setSummary] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [topFindings, setTopFindings] = useState([]);
  const [repositories, setRepositories] = useState([]);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);

      // We use Promise.allSettled to handle missing endpoints gracefully
      // since some of these might not be implemented in the backend yet.
      const [summaryRes, scansRes, findingsRes, reposRes] = await Promise.allSettled([
        dashboardAPI.getSummary(),
        dashboardAPI.getRecentScans(5),
        dashboardAPI.getTopFindings(5),
        repositoryAPI.getAll()
      ]);

      if (summaryRes.status === 'fulfilled') setSummary(summaryRes.value.data);
      else setSummary({ totalScans: 0, totalFindings: 0, criticalFindings: 0, avgNoiseReduction: 0 });

      if (scansRes.status === 'fulfilled') setRecentScans(scansRes.value.data);
      else setRecentScans([]);

      if (findingsRes.status === 'fulfilled') setTopFindings(findingsRes.value.data);
      else setTopFindings([]);

      if (reposRes.status === 'fulfilled') setRepositories(reposRes.value.data);
      else setRepositories([]);

    } catch (err) {
      setError('Failed to load some dashboard data. Backend APIs might be under construction.');
      console.error('Dashboard error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    logout();
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
              <p className="text-sm font-medium text-gray-900">{user?.username}</p>
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
              onClick={fetchDashboardData}
              className="mt-2 text-red-600 hover:text-red-700 text-sm font-medium"
            >
              Try again
            </button>
          </div>
        )}

        {summary && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <div className="bg-white rounded-lg shadow p-6">
              <p className="text-gray-600 text-sm font-medium">Total Scans</p>
              <p className="text-3xl font-bold text-gray-900 mt-2">{summary.totalScans || 0}</p>
              <p className="text-gray-500 text-xs mt-2">This month</p>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <p className="text-gray-600 text-sm font-medium">Total Findings</p>
              <p className="text-3xl font-bold text-gray-900 mt-2">{summary.totalFindings || 0}</p>
              <p className="text-gray-500 text-xs mt-2">Across all scans</p>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <p className="text-gray-600 text-sm font-medium">Critical Issues</p>
              <p className="text-3xl font-bold text-red-600 mt-2">{summary.criticalFindings || 0}</p>
              <p className="text-gray-500 text-xs mt-2">P0 Priority</p>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <p className="text-gray-600 text-sm font-medium">Noise Reduction</p>
              <p className="text-3xl font-bold text-green-600 mt-2">{summary.avgNoiseReduction || 0}%</p>
              <p className="text-gray-500 text-xs mt-2">Average filtered</p>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2">
            <div className="bg-white rounded-lg shadow mb-8">
              <div className="border-b border-gray-200 px-6 py-4">
                <h2 className="text-lg font-bold text-gray-900">Recent Scans</h2>
              </div>
              <div className="divide-y divide-gray-200">
                {recentScans.length > 0 ? (
                  recentScans.map((scan) => (
                    <div key={scan.id} className="px-6 py-4 hover:bg-gray-50 transition">
                      <div className="flex justify-between items-start">
                        <div>
                          <p className="font-medium text-gray-900">{scan.repository}</p>
                          <p className="text-sm text-gray-500">
                            {scan.branch} • {new Date(scan.timestamp).toLocaleDateString()}
                          </p>
                        </div>
                        <div className="text-right">
                          <p className="font-medium text-gray-900">{scan.totalFindings} findings</p>
                          <p className={`text-sm ${scan.status === 'COMPLETED' ? 'text-green-600' : 'text-yellow-600'}`}>
                            {scan.status}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="px-6 py-8 text-center text-gray-500">
                    <p>No scans yet. Start by connecting a repository.</p>
                  </div>
                )}
              </div>
            </div>

            <div className="bg-white rounded-lg shadow">
              <div className="border-b border-gray-200 px-6 py-4">
                <h2 className="text-lg font-bold text-gray-900">Your Repositories</h2>
              </div>
              <div className="divide-y divide-gray-200">
                {repositories.length > 0 ? (
                  repositories.map((repo) => (
                    <div key={repo.id} className="px-6 py-4 hover:bg-gray-50 transition">
                      <div className="flex justify-between items-center">
                        <div>
                          <p className="font-medium text-gray-900">{repo.name}</p>
                          <p className="text-sm text-gray-500">{repo.url}</p>
                        </div>
                        <button className="px-3 py-1 text-blue-600 hover:bg-blue-50 rounded text-sm font-medium">
                          Scan
                        </button>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="px-6 py-8 text-center text-gray-500">
                    <p>No repositories connected yet.</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow">
            <div className="border-b border-gray-200 px-6 py-4">
              <h2 className="text-lg font-bold text-gray-900">Top Findings</h2>
            </div>
            <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
              {topFindings.length > 0 ? (
                topFindings.map((finding) => (
                  <div key={finding.id} className="px-6 py-4">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <p className="font-medium text-gray-900 text-sm">{finding.ruleId}</p>
                        <p className="text-xs text-gray-500 mt-1">{finding.filePath}</p>
                      </div>
                      <span
                        className={`px-2 py-1 rounded text-xs font-medium ${
                          finding.priority === 'P0'
                            ? 'bg-red-100 text-red-800'
                            : finding.priority === 'P1'
                            ? 'bg-orange-100 text-orange-800'
                            : finding.priority === 'P2'
                            ? 'bg-yellow-100 text-yellow-800'
                            : 'bg-green-100 text-green-800'
                        }`}
                      >
                        {finding.priority}
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="px-6 py-8 text-center text-gray-500">
                  <p className="text-sm">No findings yet.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default DashboardPage;

