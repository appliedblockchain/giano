import React from 'react';
import { createRoot } from 'react-dom/client';
import { CssBaseline, ThemeProvider } from '@mui/material';
import Router from './components/Router';
import theme from './theme';

const App = () => (
  <ThemeProvider theme={theme}>
    <CssBaseline />
    <Router></Router>
  </ThemeProvider>
);

const root = createRoot(document.getElementById('root') as Element);
root.render(<App />);
