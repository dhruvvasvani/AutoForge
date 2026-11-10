import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authAPI, userAPI } from '../api/client';
import { AuthContext } from './auth-context';

const getAuthErrorMessage = (error, fallback) => {
  const responseData = error.response?.data;
  const responseMessage = responseData?.message
    || (Array.isArray(responseData?.messages) ? responseData.messages[0] : null)
    || (typeof responseData?.detail === 'string' ? responseData.detail : null);

  if (responseMessage) return responseMessage;
  if (error.request) return 'Could not connect to AutoForge. Check that the local backend is running.';
  return error.message || fallback;
};

export const AuthProvider = ({ children }) => {
  const navigate = useNavigate();
  const [user, setUser] = useState(() => {
    const savedUser = localStorage.getItem('user');
    return savedUser ? JSON.parse(savedUser) : null;
  });
  const [token, setToken] = useState(() => localStorage.getItem('authToken'));
  const [loading, setLoading] = useState(() => Boolean(localStorage.getItem('authToken')));
  const [error, setError] = useState(null);

  const login = async (email, password) => {
    try {
      setLoading(true);
      setError(null);

      const response = await authAPI.login(email, password);
      const { token, user } = response.data;

      setToken(token);
      setUser(user);

      localStorage.setItem('authToken', token);
      localStorage.setItem('user', JSON.stringify(user));

      return { success: true, user };
    } catch (err) {
      const message = getAuthErrorMessage(err, 'Login failed');
      setError(message);
      return { success: false, error: message };
    } finally {
      setLoading(false);
    }
  };

  const register = async (username, email, password, confirmPassword) => {
    try {
      setLoading(true);
      setError(null);

      if (password !== confirmPassword) {
        throw new Error('Passwords do not match');
      }

      const response = await authAPI.register(username, email, password);
      const { token, user } = response.data;

      setToken(token);
      setUser(user);

      localStorage.setItem('authToken', token);
      localStorage.setItem('user', JSON.stringify(user));

      return { success: true, user };
    } catch (err) {
      const message = err.response?.status === 409
        ? 'An account with this email already exists. Log in instead or use a different email.'
        : getAuthErrorMessage(err, 'Registration failed');
      setError(message);
      return { success: false, error: message };
    } finally {
      setLoading(false);
    }
  };

  const logout = useCallback(() => {
    setUser(null);
    setToken(null);
    setError(null);
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');
    authAPI.logout();
  }, []);

  useEffect(() => {
    if (!localStorage.getItem('authToken')) return undefined;

    let active = true;
    authAPI.getCurrentUser()
      .then((response) => {
        if (active) {
          setUser(response.data);
          localStorage.setItem('user', JSON.stringify(response.data));
        }
      })
      .catch(() => {
        if (active) {
          logout();
          setError('Your saved sign-in is no longer valid. Log in again, or create an account if you switched to a fresh local database.');
          navigate('/login', { replace: true });
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [logout, navigate]);

  const updateProfile = async (userData) => {
    try {
      setLoading(true);
      const response = await userAPI.updateProfile(userData);
      const updatedUser = response.data;

      setUser(updatedUser);
      localStorage.setItem('user', JSON.stringify(updatedUser));

      return { success: true, user: updatedUser };
    } catch (err) {
      const message = err.response?.data?.message || 'Update failed';
      setError(message);
      return { success: false, error: message };
    } finally {
      setLoading(false);
    }
  };

  const changePassword = async (oldPassword, newPassword) => {
    try {
      setLoading(true);
      await authAPI.changePassword(oldPassword, newPassword);
      return { success: true };
    } catch (err) {
      const message = err.response?.data?.message || 'Password change failed';
      setError(message);
      return { success: false, error: message };
    } finally {
      setLoading(false);
    }
  };

  const clearError = () => {
    setError(null);
  };

  const isAuthenticated = !!token && !!user;

  const hasAnyRole = (...roles) => {
    const userRole = typeof user?.role === 'string' ? user.role.toUpperCase() : '';
    return roles.some((role) => userRole === role.toUpperCase());
  };
  const isAdmin = hasAnyRole('ADMIN');

  const value = {
    user,
    token,
    loading,
    error,
    isAuthenticated,
    isAdmin,
    hasAnyRole,
    login,
    register,
    logout,
    updateProfile,
    changePassword,
    clearError,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
