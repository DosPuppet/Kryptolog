import React, { Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { PQCProvider } from './context/PQCContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThemeProvider, useTheme } from './context/ThemeContext';
import { MessengerProvider } from './context/MessengerContext';
import { NotificationProvider } from './context/NotificationContext';
import ToastContainer from './components/ui/ToastContainer';
import ConfirmDialogHost from './components/ui/ConfirmDialogHost';

// Lazy-loaded components
const Login = React.lazy(() => import('./components/Login'));
const Dashboard = React.lazy(() => import('./components/Dashboard'));
const ReceiveKeys = React.lazy(() => import('./components/transfer/ReceiveKeys'));

function AppContent() {
  const { isAuthenticated } = useAuth();
  const { isRetro, isCrashing } = useTheme();

  return (
    <div className={isCrashing ? 'crt-crash' : ''}>
      {isRetro && <div className="crt-overlay" />}
      <ToastContainer />
      <ConfirmDialogHost />
      <Suspense fallback={
        <div className="min-h-screen flex items-center justify-center bg-slate-950">
          <div className="animate-pulse text-indigo-400 text-lg font-medium">Loading…</div>
        </div>
      }>
        <Routes>
          {isAuthenticated ? (
            <>
              <Route path="/secrets" element={<Dashboard view="secrets" />} />
              <Route path="/multisig" element={<Dashboard view="multisig" />} />
              <Route path="/messenger" element={<Dashboard view="messenger" />} />
              <Route path="/proof-audit" element={<Dashboard view="proof-audit" />} />
              <Route path="*" element={<Navigate to="/secrets" replace />} />
            </>
          ) : (
            <>
              <Route path="/" element={<Login />} />
              <Route path="/receive" element={<ReceiveKeys />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </>
          )}
        </Routes>
      </Suspense>
    </div>
  );
}

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <PQCProvider>
          <MessengerProvider>
            <NotificationProvider>
              <AppContent />
            </NotificationProvider>
          </MessengerProvider>
        </PQCProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
