import React from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';

const Login = React.lazy(() => import('./Login'));
const Mint = React.lazy(() => import('./Mint'));

export default function Router() {
  return (
    <BrowserRouter basename={'/'}>
      <React.Suspense>
        <Routes>
          <Route path={'/'} element={<Navigate to={'/login'} />} />
          <Route path={'/login'} element={<Login />} />
          <Route path={'/mint'} element={<Mint />} />
        </Routes>
      </React.Suspense>
    </BrowserRouter>
  );
}
