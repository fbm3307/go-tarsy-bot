import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from '@mui/material/styles';
import { CssBaseline } from '@mui/material';
import { theme } from './theme';
import { AuthProvider } from './contexts/AuthContext';
import DashboardView from './components/DashboardView';
import SessionDetailWrapper from './components/SessionDetailWrapper';
import ManualAlertSubmission from './components/ManualAlertSubmission';

/**
 * Main App component for the Tarsy Dashboard - Enhanced with Conversation View
 * Provides React Router setup with dual session detail views (conversation + technical)
 */
function App() {
  // Debug mode - add a simple test component to see if React is working
  if (import.meta.env.DEV) {
    console.log('🚀 TARSy Dashboard App Loading...');
    console.log('Environment:', import.meta.env.MODE);
    console.log('API Base URL:', import.meta.env.VITE_API_BASE_URL);
  }

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#f5f5f5' }}>
      {/* Debug indicator */}
      {import.meta.env.DEV && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          backgroundColor: 'green',
          color: 'white',
          padding: '5px 10px',
          fontSize: '12px',
          zIndex: 9999
        }}>
          REACT WORKING ✅
        </div>
      )}

      <ThemeProvider theme={theme}>
        <CssBaseline />
        <AuthProvider>
          <Router>
            <Routes>
              {/* Main dashboard route */}
              <Route path="/" element={<DashboardView />} />
              <Route path="/dashboard" element={<DashboardView />} />

              {/* Session detail routes - Unified wrapper prevents duplicate API calls */}
              <Route path="/sessions/:sessionId" element={<SessionDetailWrapper />} />
              <Route path="/sessions/:sessionId/technical" element={<SessionDetailWrapper />} />

              {/* Manual Alert Submission route - EP-0018 */}
              <Route path="/submit-alert" element={<ManualAlertSubmission />} />

              {/* Catch-all route redirects to dashboard */}
              <Route path="*" element={<DashboardView />} />
            </Routes>
          </Router>
        </AuthProvider>
      </ThemeProvider>
    </div>
  );
}

export default App;
