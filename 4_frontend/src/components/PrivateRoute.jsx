import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const PrivateRoute = ({ element, requiredRole = null, requiredRoles = null }) => {
  const { isAuthenticated, hasAnyRole, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  const roles = requiredRoles || (requiredRole ? [requiredRole] : []);
  if (roles.length > 0 && !hasAnyRole(...roles)) {
    return <Navigate to="/dashboard" replace />;
  }

  return element;
};

export default PrivateRoute;
