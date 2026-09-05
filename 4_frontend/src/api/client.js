import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8089/api';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('authToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('authToken');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export const authAPI = {
  register: (username, email, password) =>
    apiClient.post('/auth/register', { fullName: username, email, password }),

  login: (email, password) =>
    apiClient.post('/auth/login', { email, password }),

  logout: () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');
  },

  refreshToken: () =>
    apiClient.post('/auth/refresh'),

  getCurrentUser: () =>
    apiClient.get('/auth/me'),

  validateToken: (token) =>
    apiClient.post('/auth/validate', { token }),
};

export const repositoryAPI = {
  getAll: () =>
    apiClient.get('/repositories'),

  getById: (id) =>
    apiClient.get(`/repositories/${id}`),

  create: (data) =>
    apiClient.post('/repositories', data),

  update: (id, data) =>
    apiClient.put(`/repositories/${id}`, data),

  delete: (id) =>
    apiClient.delete(`/repositories/${id}`),

  getScanHistory: (id) =>
    apiClient.get(`/repositories/${id}/scans`),
};

export const scanAPI = {
  getAll: (filters = {}) =>
    apiClient.get('/scans', { params: filters }),

  getById: (id) =>
    apiClient.get(`/scans/${id}`),

  getFindings: (scanId) =>
    apiClient.get(`/scans/${scanId}/findings`),

  getStatistics: () =>
    apiClient.get('/scans/statistics'),

  triggerScan: (repositoryId) =>
    apiClient.post(`/repositories/${repositoryId}/trigger-scan`),

  getScanStatus: (scanId) =>
    apiClient.get(`/scans/${scanId}/status`),
};

export const findingsAPI = {
  getByPriority: (priority) =>
    apiClient.get(`/findings?priority=${priority}`),

  getByReachability: (reachability) =>
    apiClient.get(`/findings?reachability=${reachability}`),

  markAsFixed: (findingId) =>
    apiClient.put(`/findings/${findingId}/mark-fixed`),

  addComment: (findingId, comment) =>
    apiClient.post(`/findings/${findingId}/comments`, { comment }),
};

export const userAPI = {
  getProfile: () =>
    apiClient.get('/users/profile'),

  updateProfile: (data) =>
    apiClient.put('/users/profile', data),

  changePassword: (oldPassword, newPassword) =>
    apiClient.post('/users/change-password', { oldPassword, newPassword }),

  getSettings: () =>
    apiClient.get('/users/settings'),

  updateSettings: (settings) =>
    apiClient.put('/users/settings', settings),
};

export const planAPI = {
  getAll: () =>
    apiClient.get('/plans'),

  getById: (id) =>
    apiClient.get(`/plans/${id}`),

  getUserPlan: () =>
    apiClient.get('/users/plan'),

  upgradePlan: (planId) =>
    apiClient.post('/users/plan/upgrade', { planId }),
};

export const dashboardAPI = {
  getSummary: () =>
    apiClient.get('/dashboard/summary'),

  getRecentScans: (limit = 10) =>
    apiClient.get(`/dashboard/recent-scans?limit=${limit}`),

  getTopFindings: (limit = 10) =>
    apiClient.get(`/dashboard/top-findings?limit=${limit}`),

  getMetrics: () =>
    apiClient.get('/dashboard/metrics'),
};

export const adminAPI = {
  getUsers: () =>
    apiClient.get('/admin/users'),

  getUserDetails: (userId) =>
    apiClient.get(`/admin/users/${userId}`),

  disableUser: (userId) =>
    apiClient.post(`/admin/users/${userId}/disable`),

  getSystemStats: () =>
    apiClient.get('/admin/statistics'),

  getScans: () =>
    apiClient.get('/admin/scans'),
};

export default apiClient;

