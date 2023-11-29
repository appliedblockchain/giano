import React from 'react';
import { createRoot } from 'react-dom/client';
import Router from './components/Router';

const App = () => <Router />;

const root = createRoot(document.getElementById('root') as Element);
root.render(<App />);
