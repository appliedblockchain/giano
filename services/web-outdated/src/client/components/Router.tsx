import React from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';

const Login = React.lazy(() => import('./Login'));
const Wallet = React.lazy(() => import('services/web/src/client/components/Wallet'));

export default function Router() {
  return (
    <BrowserRouter basename={'/'}>
      <React.Suspense>
        <Routes>
          <Route path="/" element={<Navigate to="/login" />} />
          <Route path="/login" element={<Login />} />
          <Route path="/wallet" element={<Wallet />} />
        </Routes>
      </React.Suspense>
    </BrowserRouter>
  );
}
