import React from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';

const AuthClient = React.lazy(() => import('./AuthClient'));
const AuthServer = React.lazy(() => import('./AuthServer'));
const Home = React.lazy(() => import('./Home'));

export default function Router() {
  return (
    <BrowserRouter basename={'/'}>
      <React.Suspense>
        <Routes>
          <Route path={'/'} element={<Navigate to={'/auth-client'} />} />
          <Route path={'/auth-client'} element={<AuthClient />} />
          <Route path={'/auth-server'} element={<AuthServer />} />
          <Route path={'/home'} element={<Home />} />
        </Routes>
      </React.Suspense>
    </BrowserRouter>
  );
}
