import '@testing-library/jest-dom';

// Mock environment variables for tests
(import.meta as any).env = {
  VITE_API_BASE_URL: 'http://localhost:9001',
  VITE_WS_BASE_URL: 'ws://localhost:9001'
}; 